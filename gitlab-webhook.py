#!/usr/bin/env python

import os
import re
import json
import argparse
import BaseHTTPServer
import shlex
import subprocess
import logging
import threading

logger = logging.getLogger('gitlab-webhook-processor')
logger.setLevel(logging.DEBUG)
logging_handler = logging.StreamHandler()
logging_handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                      "%B %d %H:%M:%S"))
logger.addHandler(logging_handler)

# We want to allow any repository from a trusted host
repo_host = ''
repo_dir = ''
hooks_to_handle = {"tag_push"}


class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(self):
        logger.info("Received POST request.")
        self.rfile._sock.settimeout(5)

        if 'Content-Length' not in self.headers:
            logger.debug("No Content-Length header in request")
            return self.error_response()

        json_data = self.rfile.read(
            int(self.headers['Content-Length'])).decode('utf-8')

        logger.debug("Request Data: %s" % json_data)

        try:
            data = json.loads(json_data)
        except ValueError:
            logger.error("Unable to load JSON data '%s'" % json_data)
            return self.error_response()

        hook_type = data.get('object_kind')
        if hook_type not in hooks_to_handle:
            logger.error("Unsupported hook type: %s" % hook_type)
            return self.error_response()

        repo_url = data.get('repository', {}).get('git_ssh_url')
        try:
            _, host, path = get_ssh_url_parts(repo_url)
            if host != repo_host:
                logger.error("Repo url %s doesn't match allowed host %s"
                             % (repo_url, repo_host))
                return self.error_response()
        except Exception:
            logger.exception("Exception while checking repo_url %s" % e)
            return self.error_response()
            
        repo_name = path.split('/')[-1].split('.', 1)[0]

        tag = data.get('ref', '').split('refs/tags/')[-1]
        if tag == '':
            logger.error("Unable to identify tag: '%s'" % data.get('ref', ''))
            return self.error_response()
        elif not repo_name or '/' in repo_name or repo_name in ['.', '..']:
            # Avoid feature branches, malicious branches and similar.
            logger.debug("Skipping update for repo '%s'." % repo_name)
            return self.error_response()

        # We are gonna leak repositories, but that isn't that big of a
        # deal since we are gonna re-use repositories for each tag.
        tag_addition = data['before'].replace('0', '') == ''
        tag_deletion = data['after'].replace('0', '') == ''

        post_tag_thread = threading.Thread(target=self.post_tag,
                                           args=(repo_name, tag))
        if tag_addition:
            self.add_repo(repo_url, repo_name, tag)
            post_tag_thread.start()
        elif tag_deletion:
            self.ok_response()
        else:
            self.update_repo(repo_url, repo_name, tag)
            post_tag_thread.start()
        self.ok_response()
        logger.info("Finished processing POST request.")

    def add_repo(self, url, repo, tag):
        os.chdir(repo_dir)
        repo_path = os.path.join(repo_dir, repo)
        if os.path.isdir(repo_path):
            return self.update_repo(url, repo, tag)
        run_command("git clone --depth 1 -o origin -b %s %s %s" %
                    (tag, url, repo_path))
        os.chmod(repo_path, 0770)
        logger.info("Added directory '%s'" % repo_path)

    def update_repo(self, url, repo, tag):
        repo_path = os.path.join(repo_dir, repo)
        if not os.path.isdir(repo_path):
            return self.add_branch(url, repo, tag)
        os.chdir(repo_path)
        # We want to preserve buid artifacts for performance reasons
        run_command("git clean -f")
        run_command("git fetch origin tags/%s" % tag)
        run_command("git checkout --detach FETCH_HEAD")
        run_command("git reset --hard FETCH_HEAD")
        logger.info("Updated repo '%s' to tag '%s'" % (repo, tag))

    def ok_response(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

    def post_tag(self, repo, tag):
        script = "%s/%s/post-tag" % (repo_dir, repo)
        if os.path.isfile(script):
            if os.access(script, os.X_OK):
                logger.info("Running post-tag script: %s" % script)
                run_command('%s "%s"' % (script, tag))
            else:
                logger.error("Post-install script is not executable: %s" %
                             script)

    def error_response(self):
        self.log_error("Bad Request.")
        self.send_response(400)
        self.send_header("Content-type", "text/plain")
        self.end_headers()


def run_command(command):
    logger.debug("Running command: %s" % command)
    process = subprocess.Popen(shlex.split(command.encode("ascii")),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    process.wait()
    if process.returncode != 0:
        logger.error("Command '%s' exited with return code %s: %s" %
                     (command, process.returncode, process.stdout.read()))
        return ''
    return process.stdout.read()

def get_ssh_url_parts(url):
    pattern = r'^([^@]+)@([^:]+):(.+)$'
    result = re.match(pattern, url)
    if not result:
        return result
    return result.groups()

def get_arguments():
    parser = argparse.ArgumentParser(description=(
        'Deploy tags based on GitLab tag webhook'))
    parser.add_argument('repo_host', help=(
        'Trusted repository remote host. Example: gitlab.example.com'))
    parser.add_argument('repo_dir', help=(
        'directory to clone the repos to. Example: /opt/repos'))
    parser.add_argument('-p', '--port', default=8000, metavar='8000',
                        help='server address (host:port). host is optional.')
    return parser.parse_args()


def main():
    global repo_host
    global repo_dir

    args = get_arguments()
    repo_dir = os.path.abspath(os.path.expanduser(args.repo_dir))
    repo_host = args.repo_host
    address = str(args.port)

    if address.find(':') == -1:
        host = '0.0.0.0'
        port = int(address)
    else:
        host, port = address.split(":", 1)
        port = int(port)
    server = BaseHTTPServer.HTTPServer((host, port), RequestHandler)

    logger.info("Starting HTTP Server at %s:%s." % (host, port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    logger.info("Stopping HTTP Server.")
    server.server_close()


if __name__ == '__main__':
    main()
