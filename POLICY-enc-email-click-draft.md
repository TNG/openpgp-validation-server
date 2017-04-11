Policy for validating OpenPGP Keys via Email and HTTP - Approach "enc-email-click"

This policy describes a draft automatic validation procedure
discussed at the 2016 OpenPGP Email Encryption Summit
and implemented in https://github.com/TNG/openpgp-validation-server.

A Wiki page with a summary of the discussion can be found at:
https://wiki.gnupg.org/OpenPGPEmailSummit201607/EmailValidation

Signatures covered by this policy are generated without human intervention.
They certify that at the given date, encrypted communication with the holder
of the signed key could be performed using the email address in the signed UserID.

A signature is granted if an OpenPGP public key, signed with the corresponding
private key, is sent to the Validation Server. The Validation Server then
responds by sending an email with a HTTPS URL containing a unique random nonce
to all Emails specified in the UserIds of the submitted key, also encrypted
using the submitted key. If the HTTPS URL is subsequently requested, the
originally submitted key is signed.

The lifetime of signatures using this policy is 396 days, approximately 13 months.

This Policy is a draft and may be changed or clarified.
