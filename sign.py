#!/usr/bin/env python3

import argparse
import configparser
import datetime
import locale
import logging
import logging.config
import os
import sys

from edusign import EduSign



SELFPATH = os.path.dirname(os.path.realpath(sys.argv[0]))


import json
def print_json(doc):
    print(json.dumps(doc, indent=8))



def account_selection(edusign):
    accounts = edusign.list_accounts()

    assert len(accounts) == 1, "How do we deal with several accounts?"

    return accounts[0]



def school_selection(edusign, account, school_id=None):
    if school_id is not None and school_id not in account["SCHOOL_ID"]:
        logging.error("Unknown school id %r, available schools: %r", school_id, account["SCHOOL_ID"])
        raise ValueError(f"Unknown school {school_id}")

    if school_id is None and len(account["SCHOOL_ID"]) == 1:
        school_id = account["SCHOOL_ID"][0]
        logging.debug("Only one school available, using it: %s", school_id)

    if school_id is None:
        logging.info("Several schools available and none selected, listing school infos")
        schools = edusign.schools_infos(account["SCHOOL_ID"])
        print("List of available schools:")
        for s in schools:
            print(f"\t{s['ID']}: {s['NAME']}")

    return school_id



def course_selection(edusign, school_id, course_id):
    courses = edusign.list_courses(school_id)
    course_ids = set(c["COURSE_ID"] for c in courses)

    if course_id is not None:
        if course_id in course_ids:
            return course_id

        logging.error("Unknown course id %r, available course ids: %r", course_id, course_ids)

    # TODO: select based on time
    if course_id is None and len(courses) == 1:
        course = courses[0]
        course_id = course["COURSE_ID"]
        logging.info("Only one course available, using it: %s %s", course_id, course["NAME"])
        return course_id

    now = datetime.datetime.now().astimezone()
    current_courses = []

    for c in courses:
        c["START"] = datetime.datetime.fromisoformat(c["START"]).astimezone()
        c["END"] = datetime.datetime.fromisoformat(c["END"]).astimezone()
        if c["START"] < now < c["END"] and c["PROFESSOR_SIGNATURE"] is None:
            current_courses.append(c["COURSE_ID"])

    print("List of available courses:")
    for c in courses:
        print(f"\t{c['COURSE_ID']}: {c['START']} {c['NAME']}")

    if len(current_courses) == 1:
        course_id = current_courses[0]
        logging.info("Only one course currently running and unsigned, selecting it: %s", course_id)
        return course_id

    return None



def main():
    locale.setlocale(locale.LC_ALL, '')
    logging.config.fileConfig(os.path.join(SELFPATH, "logconf.ini"), disable_existing_loggers=False)

    defcfgpath = os.path.join(SELFPATH, "edusign.ini")

    parser = argparse.ArgumentParser(description="Programme pour envoyer une signature du EduSign")
    parser.add_argument("--account", "-a", metavar="nom",
                        help="Compte du fichier de configuration à utiliser")
    parser.add_argument("--school-id", "-s", metavar="id",
                        help="ID de l'école à utiliser s'il y en a plusieurs")
    parser.add_argument("--course-id", "--cid", metavar="id",
                        help="ID du cours à utiliser s'il y en a plusieurs")
    parser.add_argument("--signature-file", "--file", metavar="path",
                        help="Chemin du fichier de signature à utiliser")
    parser.add_argument("--verbose", "-v", action="count",
                        help="Augmente le niveau de verbosité")
    parser.add_argument("--config", "-c", metavar="configfile", default=defcfgpath,
                        help="Fichier de configuration")

    args = parser.parse_args()

    verbose = args.verbose
    if verbose is not None:
        loglevels = ["WARNING", "INFO", "DEBUG", "NOTSET"]
        verbose = min(len(loglevels), verbose) - 1
        logging.getLogger().setLevel(loglevels[verbose])

    logging.info("Reading config file %s", args.config)
    config = configparser.ConfigParser()
    config.read(args.config)

    account = args.account
    if account is None:
        account = config.sections()[0]
        logging.info("No account specified with --account, using %s as a default", account)

    logging.debug("Using account %s", account)
    account = config[account]

    edusign = EduSign(account["login"], account["password"], account["method"])
    account = account_selection(edusign)

    args.school_id = school_selection(edusign, account, args.school_id)
    if args.school_id is None:
        logging.debug("No school id could be determined, stopping now")
        return

    args.course_id = course_selection(edusign, args.school_id, args.course_id)
    if args.course_id is None:
        logging.debug("No course id could be determined, stopping now")
        return

    if args.signature_file is None:
        print("No signature file provided, can't sign")
        return

    edusign.sign(args.signature_file)
    logging.info("Signature completed")



if __name__ == "__main__":
    sys.exit(main())
