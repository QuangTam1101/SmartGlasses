from __future__ import print_function
import hashlib
import os
import sys
import tarfile
import shutil
import argparse
import time
from urllib.parse import urlparse
from pathlib import Path
try:
    import requests
except ImportError:
    print("This script requires 'requests' library")
    exit(13)


class BuiltinDownloader:
    MB = 1024*1024
    BUFSIZE = 10*MB
    TIMEOUT = 60

    def print_response(self, response):
        rcode = response.status_code
        rsize = int(response.headers.get('content-length', 0)) / self.MB
        print('    {} [{:.2f} Mb]'.format(rcode, rsize))

    def make_response(self, url, session):
        pieces = urlparse(url)
        if pieces.netloc in ["docs.google.com", "drive.google.com"]:
            return session.get(url, params={'confirm': True}, stream=True, timeout=self.TIMEOUT)
        else:
            return session.get(url, stream=True, timeout=self.TIMEOUT)

    def download_response(self, response, filename):
        with open(filename, 'wb') as f:
            print('    progress ', end='')
            sys.stdout.flush()
            for buf in response.iter_content(self.BUFSIZE):
                if not buf:
                    continue
                f.write(buf)
                print('>', end='')
                sys.stdout.flush()
        print('')

    def download(self, url, filename):
        try:
            session = requests.Session()
            response = self.make_response(url, session)
            self.print_response(response)
            response.raise_for_status()
            self.download_response(response, filename)
            return True
        except Exception as e:
            print('  download failed: {}'.format(e))
            return False


class BuiltinVerifier:
    MB = 1024*1024
    BUFSIZE = 100*MB

    def verify(self, filename, expected_sum):
        if not filename.is_file():
            return False
        sha_calculator = hashlib.sha1()
        try:
            with open(filename, 'rb') as f:
                while True:
                    buf = f.read(self.BUFSIZE)
                    if not buf:
                        break
                    sha_calculator.update(buf)
            if expected_sum != sha_calculator.hexdigest():
                print('  checksum mismatch:')
                print('    expect {}'.format(expected_sum))
                print('    actual {}'.format(sha_calculator.hexdigest()))
                return False
            return True
        except Exception as e:
            print('  verify failed: {}'.format(e))
            return False


class BuiltinExtractor:
    MB = 1024*1024
    BUFSIZE = 100*MB

    def extract(self, arch, member, filename):
        if not arch.is_file():
            return False
        try:
            with tarfile.open(arch) as f:
                if member not in f.getnames():
                    print('  extract - missing member: {}'.format(member))
                    return False
                r = f.extractfile(member)
                with open(filename, 'wb') as f:
                    # print('    progress ', end='')
                    sys.stdout.flush()
                    while True:
                        buf = r.read(self.BUFSIZE)
                        if not buf:
                            break
                        f.write(buf)
                        # print('>', end='')
                        sys.stdout.flush()
            # print('')
            return True
        except Exception as e:
            print('  extract failed: {}'.format(e))
            return False


class Processor:
    def __init__(self, **kwargs):
        self.reference = kwargs.pop('reference', None)
        self.verifier = BuiltinVerifier()
        self.downloader = BuiltinDownloader()
        self.extractor = BuiltinExtractor()

    def prepare_folder(self, filename):
        filename.parent.mkdir(parents=True, exist_ok=True)

    def download(self, url, filename):
        return self.downloader.download(url, filename)

    def verify(self, mdl):
        return self.verifier.verify(mdl.filename, mdl.sha)

    def extract(self, arch, mdl):
        return self.extractor.extract(arch, mdl.member, mdl.filename)

    def ref_copy(self, mdl):
        if not self.reference:
            return False
        candidate = self.reference / mdl.filename
        if not candidate.is_file():
            return False
        print('  ref {} -> {}'.format(candidate, mdl.filename))
        try:
            if candidate.absolute() != mdl.filename.absolute():
                self.prepare_folder(mdl.filename)
                shutil.copy(candidate, mdl.filename)
            if self.verify(mdl):
                return True
            else:
                print('  ref - hash mismatch, removing')
                mdl.filename.unlink()
                return False
        except Exception as e:
            print('  ref failed: {}'.format(e))

    def cleanup(self, filename):
        print("  cleanup - {}".format(filename))
        try:
            filename.unlink()
        except Exception as e:
            print("  cleanup failed: {}".format(e))

    def handle_bad_download(self, filename):
        # rename file for further investigation
        rename_target = filename.with_suffix(filename.suffix + '.invalid')
        print('  renaming invalid file to {}'.format(rename_target))
        try:
            if rename_target.is_file():  # avoid FileExistsError on Windows from os.rename()
                rename_target.unlink()
            filename.rename(rename_target)
        except Exception as e:
            print('  rename failed: {}'.format(e))

    def get_sub(self, arch, mdl):
        print('** {}'.format(mdl.filename))
        if self.verify(mdl):
            return True
        if self.ref_copy(mdl):
            return True
        self.prepare_folder(mdl.filename)
        return self.extract(arch, mdl) and self.verify(mdl)

    def get(self, mdl):
        print("* {}".format(mdl.name))

        # Sub elements - first attempt (ref)
        if len(mdl.sub) > 0:
            if all(self.get_sub(mdl.filename, m) for m in mdl.sub):
                return True

        # File - exists or get from ref or download from internet
        verified = False
        if self.verify(mdl) or self.ref_copy(mdl):
            verified = True

        if not verified:
            self.prepare_folder(mdl.filename)
            for one_url in mdl.url:
                print('  get {}'.format(one_url))
                if self.download(one_url, mdl.filename):
                    if self.verify(mdl):
                        verified = True
                        break
            # TODO: we lose all failed files except the last one
            if not verified and mdl.filename.is_file():
                self.handle_bad_download(mdl.filename)

        if verified or self.verify(mdl):
            # Sub elements - second attempt (extract)
            if len(mdl.sub) > 0:
                return all(self.get_sub(mdl.filename, m) for m in mdl.sub)
            else:
                return True
        else:
            return False


class Model:

    def __init__(self, **kwargs):
        self.name = kwargs.pop('name', None)
        self.url = kwargs.pop('url', [])
        self.filename = Path(kwargs.pop('filename'))
        self.sha = kwargs.pop('sha', None)
        self.member = kwargs.pop('member', None)
        self.sub = kwargs.pop('sub', [])
        if not isinstance(self.url, list) and self.url:
            self.url = [self.url]
        # TODO: add completeness assertion

    def __str__(self):
        return 'Model <{}>'.format(self.name)

    def is_archive(self):
        return self.filename.is_file() and ".tar" in self.filename.suffixes

    Model(
        name='EAST',  # https://github.com/argman/EAST (a TensorFlow model), https://arxiv.org/abs/1704.03155v2 (a paper)
        url='https://www.dropbox.com/s/r2ingd0l3zt8hxs/frozen_east_text_detection.tar.gz?dl=1',
        sha='3ca8233d6edd748f7ed23246c8ca24cbf696bb94',
        filename='frozen_east_text_detection.tar.gz',
        sub=[
            Model(
                member='frozen_east_text_detection.pb',
                sha='fffabf5ac36f37bddf68e34e84b45f5c4247ed06',
                filename='frozen_east_text_detection.pb'),
        ]),

# Note: models will be downloaded to current working directory
#       expected working directory is <testdata>/dnn
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Download test models for OpenCV library")
    parser.add_argument("-d", "--dst", "--destination", help="Destination folder", default=Path.cwd())
    parser.add_argument("-l", "--list", action="store_true", help="List models")
    parser.add_argument("-r", "--ref", "--reference", help="Reference directory containing pre-downloaded models (read-only cache)")
    parser.add_argument("--cleanup", action="store_true", help="Remove archives after download")
    parser.add_argument("model", nargs='*', help="Model name to download (substring, case-insensitive)")
    args = parser.parse_args()
    ref = Path(args.ref).absolute() if args.ref else None

    # Apply filters
    filtered = []
    if args.model and len(args.model) > 0:
        for m in models:
            matches = [pat.lower() in m.name.lower() for pat in args.model]
            if matches.count(True) > 0:
                filtered.append(m)
        if len(filtered) == 0:
            print("No models match the filter")
            exit(14)
        else:
            print("Filtered: {} models".format(len(filtered)))
    else:
        filtered = models

    # List models
    if args.list:
        for mdl in filtered:
            print(mdl.name)
        exit()

    # Destination directory
    dest = Path(args.dst)
    if not dest.is_dir():
        print('  creating directory: {}'.format(dest))
        dest.mkdir(parents=True, exist_ok=True)
    os.chdir(dest)

    # Actual download
    proc = Processor(reference=ref)
    results = dict()
    for mdl in filtered:
        t = time.time()
        results[mdl] = proc.get(mdl)
        print("* {} ({:.2f} sec)".format("OK" if results[mdl] else "FAIL", time.time() - t))

    # Result handling
    for (mdl, res) in results.items():
        if args.cleanup and res and mdl.is_archive():
            proc.cleanup(mdl.filename)
        if not res:
            print("FAILED: {} - {}".format(mdl.name, mdl.filename))
    if list(results.values()).count(False) > 0:
        exit(15)
    else:
        print("SUCCESS")
