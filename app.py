import inspect
import json
import os
import pprint
import re
import requests
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from dotenv import load_dotenv
from flask import Flask, request
from pathlib import Path
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from slack_bolt.oauth.oauth_settings import OAuthSettings
from slack_bolt.oauth.callback_options import CallbackOptions, SuccessArgs, FailureArgs
from slack_bolt.response import BoltResponse

########################################
#               ENV VARS               #
########################################

load_dotenv()

GITLAB_TOKEN = os.getenv('GITLAB_TOKEN')
GITLAB_URL = os.getenv('GITLAB_URL')
KEY_VAULT_NAME = os.getenv('KEY_VAULT_NAME')
SLACK_BOT_TOKEN = os.getenv('SLACK_BOT_TOKEN')
SLACK_CHANNEL = os.getenv('SLACK_CHANNEL')
SLACK_CLIENT_ID = os.getenv('SLACK_CLIENT_ID')
SLACK_CLIENT_SECRET = os.getenv('SLACK_CLIENT_SECRET')
SLACK_SIGNING_SECRET = os.getenv('SLACK_SIGNING_SECRET')

########################################
#               TOOLS                  #
########################################


def find_by_key(data, target):
    for k, v in data.items():
        if k == target:
            return v
        elif isinstance(v, dict):
            return find_by_key(v, target)
        elif isinstance(v, list):
            for i in v:
                if isinstance(i, dict):
                    return find_by_key(i, target)


def get_mr_url(url):
    prt = url.partition("/merge_requests/")
    project_name = prt[0].rsplit(sep="/", maxsplit=1)[1]
    mergerequest_id = re.sub("\D", "", url)
    project_id = project_ids[project_name]
    url_base = f"https://{GITLAB_URL}/api/v4"

    return f'{url_base}/projects/{project_id}/merge_requests/{mergerequest_id}'


def format_block(title, author_url, author_name, project_id, state, upvotes, web_url):
    frame = inspect.currentframe()
    try:
        args, _, _, values = inspect.getargvalues(frame)
        txt = Path("templates/block_mr.json").read_text()
        for arg in args:
            txt = re.sub(f'\${arg}\$', f'{values[arg]}', txt)
    finally:
        del frame
        return txt


########################################
#               GITLAB                 #
########################################

headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}
url_base = f"https://{GITLAB_URL}/api/v4"

########################################
#           AZURE KEY VAULT            #
########################################

"""
kv_url = f'https://{KEY_VAULT_NAME}.vault.azure.net'
kv_credential = DefaultAzureCredential()
kv_client = SecretClient(vault_url=kv_url, credential=kv_credential)
"""

########################################
#                USERS                 #
########################################


class Users:
    pass


def load_users() -> dict:
    # Azure Key Vault
    """
    # Store all users in the same secret or multiple secrets? Need to decide
    # Same secret
    return json.loads(kv_client.get_secret("users").value)
    # Multiple secrets
    #for user_name in json.loads(kv_client.get_secret("user_names").value)['user_names']:
    #    users[user_name] = json.loads(kv_client.get_secret(user_name).value)
    """
    # JSON file
    with open("data/users.json", "r") as f:
        return json.load(f)


def add_user(user_name, gitlab_token=None, slack_id=None, slack_token=None):
    # Azure Key Vault
    """
    user_old = users[user_name]
    user_new = {
        "gitlab_token": gitlab_token if gitlab_token else user_old['gitlab_token'],
        "slack_id": slack_id if slack_id else user_old['slack_id'],
        "slack_token": slack_token if slack_token else user_old['slack_token'],
    }
    users[user_name] = user_new
    kv_client.set_secret(f'user_name', user_new)
    """
    # JSON file
    user_old = users[user_name]
    user_new = {
        "gitlab_token": gitlab_token if gitlab_token else user_old['gitlab_token'],
        "slack_id": slack_id if slack_id else user_old['slack_id'],
        "slack_token": slack_token if slack_token else user_old['slack_token'],
    }
    users[user_name] = user_new
    with open("data/users.json", "w") as o:
        json.dump(users, o, indent=4)


users = load_users()
slack_ids = {user['slack_id']: user for user in users}

########################################
#              PROJECTS                #
########################################


class Projects(dict):

    def __init__(self):
        dict.__init__(self)

    def load(self):
        with open("data/projects.json", "r") as f:
            self.update(json.load(f))

    def add(self, name, id):
        self[name] = id


projects = Projects()
projects.load()
project_ids = {projects[project]: project for project in projects}

########################################
#            MERGE REQUESTS            #
########################################


class MergeRequests(dict):

    def __init__(self):
        dict.__init__(self)

    def load(self):
        self.update()

    def add(self, iid, mr):
        self[iid] = mr

    def by_state():
        pass

    def by_author():
        pass

    def by_date():
        pass


def load_merge_requests(projects: dict) -> dict:

    merge_requests = {project: {} for project in projects}

    for project in projects:
        url = f'{url_base}/projects/{projects[project]}'
        mrs = requests.get(f'{url}/merge_requests', params={"state": "opened"}, headers=headers).json()
        for mr in mrs:
            if mr['author']['username'] in users:
                merge_requests[project_ids[str(mr['project_id'])]][mr['iid']] = {
                    "title": mr['title'],
                    "state": mr['state'],
                    "created_at": mr['created_at'],
                    "updated_at": mr['updated_at'],
                    "upvotes": mr['upvotes'],
                    "username": mr['author']['username'],
                    "user_url": mr['author']['web_url'],
                    "web_url": mr['web_url']
                }

    return merge_requests


merge_requests = load_merge_requests()


def add_merge_request(merge_requests: dict, merge_request: dict) -> dict:
    project_id = merge_request['project']['id']
    iid = merge_request['object_attributes']['iid']
    title = merge_request['object_attributes']['title']
    state = merge_request['object_attributes']['state']
    created_at = merge_request['object_attributes']['created_at']
    updated_at = merge_request['object_attributes']['updated_at']
    upvotes = "0"
    username = merge_request['user']['username']
    web_url = merge_request['object_attributes']['url']

    merge_requests[project_ids[str(project_id)]][iid] = {
        "title": title,
        "state": state,
        "created_at": created_at,
        "updated_at": updated_at,
        "upvotes": upvotes,
        "username": username,
        "web_url": web_url
    }

    message = format_block(title=title, author_name=username, project_id=project_id,
                           state=state, upvotes=upvotes, web_url=web_url)

    notify_slack(slack_app=app, blocks=message)

    return merge_requests


def notify_slack(slack_app: App, blocks: str, text: str = ""):
    slack_app.client.chat_postMessage(token=SLACK_BOT_TOKEN, channel=SLACK_CHANNEL, text=text, blocks=blocks)


def delete_mr():
    pass


def notify_delete():
    pass


def update_list():
    pass


########################################
#               CALLBACK               #
########################################


def success(args: SuccessArgs) -> BoltResponse:
    assert args.request is not None

    add_user(user_name=app.client.users_info(token=SLACK_BOT_TOKEN, user=args.installation.user_id)['user']['name'],
             slack_id=args.installation.user_id,
             slack_token=args.installation.user_token)

    return BoltResponse(
        status=200,
        body="User token creation sucess :)"
    )


def failure(args: FailureArgs) -> BoltResponse:
    assert args.request is not None
    assert args.reason is not None

    return BoltResponse(
        status=args.suggested_status_code,
        body="User token creation fail :("
    )


########################################
#               BOLT                   #
########################################

oauth_settings = OAuthSettings(
    client_id=SLACK_CLIENT_ID,
    client_secret=SLACK_CLIENT_SECRET,
    user_scopes=["reactions:write"],
    callback_options=CallbackOptions(success=success, failure=failure)
)

app = App(
    signing_secret=SLACK_SIGNING_SECRET,
    oauth_settings=oauth_settings
)

########################################
#               EVENTS                 #
########################################


@app.event("reaction_added")
def handle_reaction_added(context, event, body, request, req, payload):
    if event['reaction'] == '+1':
        result = app.client.conversations_history(token=SLACK_BOT_TOKEN, channel=event['item']['channel'],
                                                  inclusive=True, oldest=event['item']['ts'], limit=1)
        url_given = find_by_key(result['messages'][0], "url")

        mr = requests.post(f'{get_mr_url(url_given)}/award_emoji?name=thumbsup', headers=headers).json()
    pprint.pprint(mr)


@app.event("reaction_removed")
def handle_reaction_removed(event):
    if event['reaction'] == '+1':
        result = app.client.conversations_history(token=SLACK_BOT_TOKEN, channel=event['item']['channel'],
                                                  inclusive=True, oldest=event['item']['ts'], limit=1)
        url_given = find_by_key(result['messages'][0], "url")

        emojis = requests.get(f'{get_mr_url(url_given)}/award_emoji', headers=headers).json()
        for emoji in emojis:
            if emoji['user']['username'] == slack_ids[event['user']]:
                award_id = emoji['id']

        requests.delete(f'{get_mr_url(url_given)}/award_emoji/{award_id}', headers=headers)


@app.message("merge_requests")
def handle_mr_added(message, say, event):
    url_given = find_by_key(message, "url")

    mr = requests.get(get_mr_url(url_given), headers=headers).json()

    blocks = format_block(title=mr['title'], author_url=mr['author']['web_url'], author_name=mr['author']['name'],
                          project_id=mr['project_id'], state=mr['state'], upvotes=mr['upvotes'], web_url=mr['web_url'])

    say(token=SLACK_BOT_TOKEN, text="", blocks=blocks)

########################################
#              / COMMANDS              #
########################################


@app.command("/openmr")
def message_history(ack, say, context, event):
    ack()
    ok = app.client.conversations_history(token=SLACK_BOT_TOKEN, channel=context['channel_id'])

    message_list = set()
    for message in ok['messages']:
        message_list.add(find_by_key(message, "url"))
    message_list.remove(None)

    pprint.pprint(message_list)


"""
    blocks = []
    blocks.append(
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Open Merge Requests"
            }
        }
    )
    for message in message_list:
        headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}
        mr = requests.get(get_mr_url(message), headers=headers).json()
        if mr['state'] == "opened":
            blocks.extend((
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{mr['title']}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Created by:*\n<{mr['author']['web_url']}|{mr['author']['name']}>"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Project:*\n{[key for key, value in project_ids.items() if value == mr['project_id']][0]}"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*State:*\n{mr['state']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Thumbs Up:*\n{mr['upvotes']} :thumbsup:"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"<{mr['web_url']}|View merge request>"
                }
            },
            {
                "type": "divider"
            }
            ))

    say(token=SLACK_BOT_TOKEN, blocks=blocks)
"""

########################################
#               FLASK                  #
########################################


flask_app = Flask(__name__)
handler = SlackRequestHandler(app)


@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    return handler.handle(request)


@flask_app.route("/slack/install", methods=["GET"])
def slack_install():
    return handler.handle(request)


@flask_app.route("/slack/oauth_redirect", methods=["GET"])
def slack_oauth_redirect():
    return handler.handle(request)
