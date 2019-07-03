# WIP: wotsap parser
import json
import os


# TODO: since the wotsap website is all fubar'd, I've hacked it up to read
# /tmp/report. You can generate this with 'wotsap >/tmp/report'
class PgpReport:
    """Class for retrieving and processing wotsap reports."""

    kURL = "http://webware.lysator.liu.se/jc/wotsap/wots/latest/keystatistics/"
    kDATAFILE = ".gpg_report"
    kSIGNED = "SIGNED"
    kNOT_SIGNED = "NOTSIGNED"

    def __init__(self, keyid, clear_data, keyring=None):
        self.keyid = keyid
        self.need_upload = []
        self.need_to_sign = []
        self.might_need_to_sign = []
        self.need_sigs_from = []
        self.sign_data = {}
        self.datafile = "%s/%s" % (os.path.expanduser("~"), self.kDATAFILE)
        self.keys = []
        if keyring:
            self.keys = self._get_keyring_keyids(keyring)

        self._get_wotsap_report()
        if clear_data:
            self.clear_datafile()
        else:
            self._read_datafile()

    def get_need_to_sign(self):
        """Accessor for need_to_sign."""
        return self.need_to_sign

    def get_need_upload(self):
        """Accessor for need_upload."""
        return self.need_upload

    def clear_datafile(self):
        os.remove(self.datafile)

    def _read_datafile(self):
        """Read our data file."""
        if not os.path.exists(self.datafile):
            return
        f = open(self.datafile, "r")
        d = ""
        for l in f:
            d += l
        self.sign_data = json.read(d)
        f.close()

    def _write_datafile(self):
        """Write our data file."""
        f = open(self.datafile, "w")
        f.write(json.write(self.sign_data))
        f.close()

    def _get_wotsap_report(self):
        """Get wotsap report for a key."""
        # url = '%s0x%s.txt' % (self.kURL, self.keyid)
        # report = urllib2.urlopen(url)
        # self._parse_wotsap_report(report)
        # report.close()
        f = open("/tmp/report", "r")
        self._parse_wotsap_report(f)
        f.close()

    def _parse_wotsap_report(self, report):
        """Parse the wotsap report."""
        for line in report:
            if line.startswith("This key is signed by, excluding"):
                line = report.next()
                while not line.startswith("Total:"):
                    self.might_need_to_sign.append(line.strip().split()[1])
                    line = report.next()

            if line.startswith("Keys signed by this key, excluding"):
                line = report.next()
                while not line.startswith("Total:"):
                    self.need_sigs_from.append(line.strip().split()[1])
                    line = report.next()

    def check_for_upload_needed(self):
        """Walk through keys without our sig and determine their status."""
        copy = []
        copy.extend(self.might_need_to_sign)
        for keyid in copy:
            if self.keys and keyid not in self.keys:
                continue
            if keyid in self.sign_data:
                if self.sign_data[keyid] == self.kSIGNED:
                    self.need_upload.append(keyid)
                    self.might_need_to_sign.remove(keyid)
                else:
                    self.need_to_sign.append(keyid)
                    self.might_need_to_sign.remove(keyid)
            else:
                signed = ""
                while signed not in ("y", "Y", "n", "N", "yes", "no"):
                    signed = input("Have you signed key %s? " % keyid)

                if signed in ("y", "Y", "yes"):
                    self.sign_data[keyid] = self.kSIGNED
                    self.need_upload.append(keyid)
                    self.might_need_to_sign.remove(keyid)
                else:
                    self.sign_data[keyid] = self.kNOT_SIGNED
                    self.need_to_sign.append(keyid)
                    self.might_need_to_sign.remove(keyid)
        if not self.keys:
            assert not self.might_need_to_sign
        self._write_datafile()

    def _get_keyring_keyids(self, keyring):
        """Get all the keyids off of a keyring."""
        keys = []
        gpg = os.popen(
            "gpg --fixed-list-mode --with-colons --no-default-keyring"
            " --keyring %r --fingerprint" % keyring
        )
        for line in gpg:
            if not line.startswith("fpr"):
                continue
            keys.append("0x%s" % line.split(":")[9][-8:])
        gpg.close()
        return keys
