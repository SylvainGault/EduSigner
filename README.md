# EduSign Auto Signer

## Instructions
First create a file `edusign.ini` taking example from `edusign.ini.example` in
the same directory. Then run `sign.py` with the appropriate options.

## Config file format
The format of the file `edusign.ini` is an ini config file. Each section is a
user account, the section name is only used by this program to identify them.
The following variables are available.

- `method`: Either `plain` or `MSAuth` depending on the authentication mechanism used by your organisation. `plain` is just a password usually entered directly on the edusign website. `MSAuth` is the case where the authentication is delegated to Microsoft.
- `login`: The login to log into edusign via the `plain` or `MSAuth` method.
- `password`: The password to log into edusign for both authentication methods.

## Options
The following options to the program `sign.py` are available.

- `--acount` or `-a` gives the name of the account in the config file.
- `--school-id` or `-s` allows to provide the id of the school. If there's only
one school for your account, it is selected automatically. If there's more than
one, they are listed.
- `--course-id` or `--cid` allows to provide the id of the course to sign for.
If there's only one course and none is provided, it is selected automatically.
If there's more than one they are listed.
- `--signature-file` or `--file` allows to provide the PNG file to sign with.
It should be the right size, although this is not enforced.
- `--config` or `-c` allows to provide the path of the config file. It must
follow the format described above.
