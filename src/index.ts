import * as AWS from "aws-sdk";
import { createHash } from "crypto";
import * as fs from "fs";
import * as greenlock from "greenlock";
import * as dnsChallenge from "le-challenge-dns";
import * as certbotStore from "le-store-certbot";
import { debug, error, info } from "winston";
import winston = require("winston");
import { Mail } from "winston-mail";
import * as yargs from "yargs";

interface Config {
    logLevel: string;
    awsCredentialsFile: string;
    domains: string[];
    awsHostedZoneId: string;
    email: string;
    reportsToEmail?: string;
    smtpHost: string;
    smtpPort: number;
    storageRootDir: string;
    leServer: "staging" | "production" | string;
}

function run(): void {
    const args = loadArgs();
    const config = guard(() => loadConfig(args), (err) => error("Can't load config:", err));
    guard(() => initLogging(config), (err) => error("Can't initialize logging:", err))
        .then(() => {
            info("Config loaded.");
            info("Initializing Route53 connection.");
            const r53 = guard(
                () => initRoute53Client(config),
                (err) => error("Can't initalize Route53 connection:", err));
            info("Initializing LetsEncrypt.");
            const le = guard(
                () => initLetsencryptConnection(config, r53),
                (err) => error("Can't initalize LetsEncrypt:", err));
            info("Updating certificates.");
            guard(
                () => updateCertificates(config, le),
                (err) => error("Certificate update error:", err));
        }).catch(() => undefined);
}

function guard<T>(fun: () => T, onErr: (e: Error) => void): T {
    try {
        return fun();
    } catch (err) {
        onErr(err);
        throw err;
    }
}

function loadArgs(): string {

    const args = yargs
        .usage("Usage: $0 [options]")
        .options("config", {
            alias: "c",
            default: "./config.json",
            describe: "Read setting from specified config file path",
            type: "string",
        })
        .locale("en")
        .version()
        .help("help")
        .strict()
        .argv;

    return args.config as string;
}

function loadConfig(filename: string): Config {
    const json = JSON.parse(fs.readFileSync(filename).toString());
    return mergeConfigDefaults(json);
}

function mergeConfigDefaults(json: Partial<Config>): Config {

    function requireField<T, K extends keyof T>(obj: Partial<T>, key: K): T[K] {
        const val = obj[key];
        if (val === undefined) {
            throw new Error(`Missing ${key} in configuration file.`);
        } else {
            return val as T[K];
        }
    }

    return {
        awsCredentialsFile: json.awsCredentialsFile || "./credentials",
        awsHostedZoneId: requireField(json, "awsHostedZoneId"),
        domains: requireField(json, "domains"),
        email: requireField(json, "email"),
        leServer: json.leServer || "production",
        logLevel: json.logLevel || "info",
        reportsToEmail: json.reportsToEmail,
        smtpHost: json.smtpHost || "localhost",
        smtpPort: json.smtpPort || 25,
        storageRootDir: json.storageRootDir || "~/le",
    };
}

async function initLogging(config: Config): Promise<void> {
    winston.configure({
        level: config.logLevel,
        transports: [
            new winston.transports.Console({
                // colorize: true,
                debugStdout: true,
                // prettyPrint: true,
            }),
        ],
    });
    if (config.reportsToEmail) {
        winston.add(Mail, // {
            // host: config.smtpHost,
            // level: "error",
            // port: config.smtpPort,
            // subject: "LE cert update {{level}}: {{msg}}",
            // to: config.reportsToEmail,
        // }
        );
        info(`Initialized email reporting to ${config.reportsToEmail}`);
        await timeout(100);
        return;
    } else {
        return;
    }
}

async function timeout(ms: number): Promise<void> {
    return new Promise<void>((resolve) => {
        setTimeout(resolve, ms);
    });
}

function initRoute53Client(config: Config): AWS.Route53 {
    AWS.config.credentials = new AWS.SharedIniFileCredentials({
        filename: config.awsCredentialsFile,
    });
    AWS.config.logger = {
        log: (...messages: Array<{}>) => {
            for (const m of messages) {
                debug(m.toString());
            }
        },
    };
    return new AWS.Route53();
}

function initLetsencryptConnection(config: Config, r53: AWS.Route53): greenlock.LetsEncrypt {
    const challenge = dnsChallenge.create();
    const digest: { value: string } = { value: "" };
    challenge.set = makeChallegeSetter(r53, config.awsHostedZoneId, digest);
    challenge.remove = makeChallegeRemover(r53, config.awsHostedZoneId, digest);
    const store = certbotStore.create({
        configDir: config.storageRootDir,
        logsDir: ":configDir/logs",
        workDir: ":configDir/work",
    });
    return greenlock.create({
        challengeType: "dns-01",
        challenges: {
            "dns-01": challenge,
        },
        log: (_d, ...msgs) => { debug(msgs.join(" ")); },
        server: config.leServer,
        store,
    });
}

type ChallengeSetter = (
    args: greenlock.Args,
    domain: string,
    challenge: string,
    keyAuthorization: string,
    cb: () => void,
) => void;

function makeChallegeSetter(
    r53: AWS.Route53,
    zoneId: string,
    digest: { value: string },
): ChallengeSetter {
    return (_args, domain, _challenge, keyAuthorization, cb) => {
        const domainName = "_acme-challenge." + domain;
        digest.value = createHash("sha256").update(keyAuthorization).digest("base64")
            .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

        const input: AWS.Route53.Types.ChangeResourceRecordSetsRequest = {
            ChangeBatch: {
                Changes: [
                    {
                        Action: "UPSERT",
                        ResourceRecordSet: {
                            Name: domainName,
                            ResourceRecords: [{ Value: `\"${digest.value}\"` }],
                            TTL: 300,
                            Type: "TXT",
                        },
                    },
                ],
                Comment: "letsencrypt challenge",
            },
            HostedZoneId: zoneId,
        };
        r53.changeResourceRecordSets(input).promise().then((data) => {
            info(`Successfully set DNS challenge for ${domain}. ` +
                `Waiting for pending change to propagate.`);
            waitForChange(0, r53, data.ChangeInfo.Id, () => {
                info(`Changes propagation for ${domain} challenge are complete.`);
                cb();
            });
        }).catch((err) => {
            error(`Can't set DNS chalenge for ${domain}:`, err);
            throw err;
        });
    };
}

function makeChallegeRemover(r53: AWS.Route53, zoneId: string, digest: { value: string }):
    (args: greenlock.Args, domain: string, challenge: string, cb: () => void) => void {
    return (_args, domain, _challenge, cb) => {
        const domainName = "_acme-challenge." + domain;
        const input: AWS.Route53.Types.ChangeResourceRecordSetsRequest = {
            ChangeBatch: {
                Changes: [
                    {
                        Action: "DELETE",
                        ResourceRecordSet: {
                            Name: domainName,
                            ResourceRecords: [{ Value: `\"${digest.value}\"` }],
                            TTL: 300,
                            Type: "TXT",
                        },
                    },
                ],
                Comment: "letsencrypt challenge",
            },
            HostedZoneId: zoneId,
        };
        r53.changeResourceRecordSets(input).promise().then(() => {
            info(`Successfully removed DNS challenge for ${domain}`);
            cb();
        }).catch((err) => {
            error(`Can't remove DNS challenge for ${domain}:`, err);
            throw err;
        });
    };
}

const MAX_WAIT_ATTEMPTS = 600;

function waitForChange(attempt: number, r53: AWS.Route53, id: string, cb: () => void): void {
    debug("Checking if DNS changes have propagated.");
    r53.getChange({ Id: id }).promise()
        .then((data) => {
            if (data.ChangeInfo.Status === "PENDING") {
                if (attempt > MAX_WAIT_ATTEMPTS) {
                    throw new Error(
                        `Max DNS propagation checks attempts (${MAX_WAIT_ATTEMPTS}) exceeded.`);
                }
                setTimeout(() => waitForChange(attempt + 1, r53, id, cb), 1000);
            } else {
                cb();
            }
        })
        .catch((err) => {
            error("Changes propagation reading error:", err);
            throw err;
        });
}

function updateCertificates(config: Config, le: greenlock.LetsEncrypt): void {
    const opts: greenlock.RegisterOptions = {
        agreeTos: true,
        challengeType: "dns-01",
        domains: config.domains,
        email: config.email,
    };
    le.register(opts)
        .then((cert) => {
            info(`Active LE certificate is stored. Subject: ${cert.subject}, ` +
                `alt names: ${cert.altnames}`);
            const names = new Set([cert.subject].concat(cert.altnames));
            if (!isSuperset(names, new Set(config.domains))) {
                info("Some required domains are missing. Renewing the cert.");
                opts.duplicate = true;
                return le.renew(opts, cert);
            }
            return Promise.resolve(cert);
        })
        .catch((err) => {
            throw err;
        });
}

function isSuperset<T>(thisSet: Set<T>, subset: Set<T>): boolean {
    for (const elem of subset) {
        if (!thisSet.has(elem)) {
            return false;
        }
    }
    return true;
}

run();
