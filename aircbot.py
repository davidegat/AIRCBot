import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext, messagebox
import threading
import requests
import feedparser
from datetime import datetime
import time
import hashlib
import irc.client
import os

# File paths for prompts and help
SYSTEM_PROMPT_FILE = "system_prompt.txt"
SUMMARY_PROMPT_FILE = "summary_prompt.txt"
HELP_TEXT_FILE = "help_text.txt"

# Log dir configuration
LOG_DIR = "user_logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Customize RSS feed
FEED_URL = "https://www.ansa.it/english/news/english_nr_rss.xml"

# Configurable LLM endpoint
LLM_ENDPOINT = "http://localhost:1234/v1/chat/completions"

# Default options at startup (user can modify them via UI)
nck = "Egidio"          # Nick
srv = "ssl.ircnet.ovh"  # Server
prt = "6667"            # Port
chn = "#casale"         # Channel

# Configuration ends here.

def load_prompt(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        return ""


SYSTEM_PROMPT_TEMPLATE = load_prompt(SYSTEM_PROMPT_FILE)
SUMMARY_PROMPT_TEMPLATE = load_prompt(SUMMARY_PROMPT_FILE)
HELP_TEXT = load_prompt(HELP_TEXT_FILE)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def fetch_news_from_feed(max_items=2):
    feed = feedparser.parse(FEED_URL)
    items = []
    for entry in feed.entries[:max_items]:
        items.append({"title": entry.title, "link": entry.link})
    return items


def append_to_user_log(logging_enabled, nickname, summary):
    if not logging_enabled:
        return

    log_file = os.path.join(LOG_DIR, f"{nickname}.log")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now()}]\n{summary}\n\n")


def ask_LLM(
    query,
    conversation_history,
    bot_nickname,
    server,
    channel,
    speaker_nickname,
    log_callback=None,
    logging_enabled=False,
):
    if (
        conversation_history
        and conversation_history[0]["role"] == "system"
        and conversation_history[0]["content"] == SUMMARY_PROMPT_TEMPLATE
    ):
        (
            log_callback(f"LLM - Handling summary request...", bold=True)
            if log_callback and logging_enabled
            else None
        )
        request_messages = conversation_history
    else:
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        news_items = fetch_news_from_feed(max_items=5)
        if news_items:
            news_section = "\n".join(
                [
                    f"{idx}) {item['title']}\n {item['link']}"
                    for idx, item in enumerate(news_items, start=1)
                ]
            )
        else:
            news_section = "No news found."

        system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
            bot_nickname=bot_nickname,
            server=server,
            channel=channel,
            speaker_nickname=speaker_nickname,
            current_datetime=current_datetime,
            news_section=news_section,
        )

        request_messages = [{"role": "system", "content": system_prompt}]
        request_messages.extend(conversation_history)
        if query:
            brief_query = f"{query.strip()} (please answer briefly)"
            request_messages.append({"role": "user", "content": brief_query})

    if len(request_messages) > 5:
        request_messages = request_messages[-5:]

    data = {"messages": request_messages}
    url = LLM_ENDPOINT
    headers = {"Content-Type": "application/json"}

    # Example integration with OpenAI's API:
    #
    # To enable communication with OpenAI's GPT models, follow these steps:
    #
    # 1. Install the OpenAI Python library if not already installed: pip install openai
    #
    # 2. Import the library at the top of your script: import openai
    #
    # 3. Replace the local LLM request code in the `ask_LLM` function with the following:
    #
    #    a. Ensure your OpenAI API key is set securely. For example:
    #
    #       openai.api_key = "your_openai_api_key_here"
    #
    #    b. Call OpenAI's API with the conversation history and specify the desired model:
    #
    #       response = openai.ChatCompletion.create(
    #           model="gpt-4",  # Specify the GPT model version (e.g., gpt-3.5-turbo or gpt-4)
    #           messages=conversation_history,  # Pass the chat history as the messages parameter
    #           temperature=0.7,  # Adjust temperature for response variability (optional)
    #       )
    #
    #    c. Extract the assistant's message content and role from the response:
    #
    #       assistant_message = response["choices"][0]["message"]
    #       content = assistant_message["content"]
    #       role = assistant_message["role"]
    #
    #    d: Append the assistant's message to the conversation history:
    #
    #       conversation_history.append(assistant_message)
    #       return content, role
    #
    # 4. Replace `your_openai_api_key_here` with your actual API key or store it securely in environment variables.
    #    Example of setting the API key in your environment:
    #
    #    export OPENAI_API_KEY="your_openai_api_key_here"
    #
    #    Then, retrieve it in Python:
    #
    #    openai.api_key = os.getenv("OPENAI_API_KEY")
    #
    #
    # Note: The OpenAI API requires an active subscription or billing setup. Less privacy is expected too.

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        assistant_message = result["choices"][0]["message"]
        content = assistant_message["content"]
        role = assistant_message["role"]
        return content, role
    except requests.exceptions.ConnectionError:
        if log_callback and logging_enabled:
            log_callback(
                "BOT - LLM unreachable! Make sure local LLM is up and running!",
                bold=True,
            )
        raise
    except Exception as e:
        if log_callback and logging_enabled:
            log_callback(f"LLM - Unexpected issue: {str(e)}", bold=True)
        raise


class IRCBot:
    def __init__(
        self,
        server,
        port,
        nickname,
        channel,
        password,
        log_callback=None,
        logging_var=True,
    ):
        self.server = server
        self.port = port
        self.nickname = nickname
        self.channel = channel
        self.password_hash = hash_password(password)
        self.log_callback = log_callback
        self.logging_enabled = logging_var
        self.authenticated_users = {}
        self.failed_attempts = {}
        self.last_attempt_time = {}
        self.client = irc.client.Reactor()
        self.connection = None
        self.keep_alive_interval = 60
        self.logged_messages = set()
        self.exclude_keywords = [
            "end of names list",
            "+i",
            "privmsg",
            "pong",
            "action",
            "001",
            "002",
            "003",
            "004",
            "005",
            "020",
            "042",
            "251",
            "252",
            "253",
            "254",
            "255",
            "256",
            "265",
            "266",
            "353",
            "366",
            "372",
            "375",
            "376",
        ]
        self.conversation_history = []
        self.ignore_list = set()
        self.user_conversations = {}
        self.user_message_buffer = {}

    def connect(self):
        if self.log_callback:
            self.log_callback(
                "LLM - Please always make sure local LLM is up and running!"
            )
            self.log_callback(
                "BOT - If you modified me, check your endpoint and connection."
            )
            self.log_callback(
                "_____________________________________________________ ____ __ _ _"
            )
            self.log_callback(
                f"BOT - Connecting to IRC ({self.server} port {self.port})...",
                bold=True,
            )
        try:
            self.connection = self.client.server().connect(
                self.server, int(self.port), self.nickname
            )
            self.connection.add_global_handler("all_events", self.handle_server_message)
            self.connection.add_global_handler("ctcp", self.handle_ctcp_message)
            self.start_keep_alive()
            threading.Thread(target=self.client.process_forever, daemon=True).start()
            if self.log_callback:
                self.log_callback(f"BOT - {self.server} is up!", bold=True)
                self.log_callback(
                    "_____________________________________________________ ____ __ _ _"
                )
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"\nBOT - Error connecting: {e}\n", bold=True)

    def handle_ctcp_message(self, connection, event):
        if event.arguments[0].lower() == "action":
            source = irc.client.NickMask(event.source).nick
            message = event.arguments[1] if len(event.arguments) > 1 else ""

            if self.log_callback:
                self.log_callback(
                    "_____________________________________________________ ____ __ _ _"
                )
                self.log_callback(f"IRC - ACTION: {source} {message}", bold=True)

            if source not in self.authenticated_users:
                self.request_authentication(source)
            elif self.authenticated_users.get(source, False):
                if source not in self.user_conversations:
                    self.user_conversations[source] = [
                        {"role": "system", "content": ""}
                    ]

                self.log_callback(
                    f"LLM - Generating reply for ACTION from {source}...",
                    bold=True,
                )

                response, role = ask_LLM(
                    query=message,
                    conversation_history=self.user_conversations[source],
                    bot_nickname=self.nickname,
                    server=self.server,
                    channel=self.channel,
                    speaker_nickname=source,
                    log_callback=self.log_callback,
                )

                self.user_conversations[source].append(
                    {"role": "user", "content": message}
                )
                self.user_conversations[source].append(
                    {"role": "assistant", "content": response}
                )

                self.send_message(source, response)
            else:
                self.check_password(source, message)

    def join_channel(self):
        if self.connection:
            try:
                self.connection.join(self.channel)

            except Exception as e:
                if self.log_callback:
                    self.log_callback(
                        f"\nBOT - Error joining {self.channel}: {e}\n", bold=True
                    )

    def start_keep_alive(self):
        if self.connection:
            self.connection.ping(self.server)
            self.client.scheduler.execute_after(
                self.keep_alive_interval, self.start_keep_alive
            )

    def disconnect(self):
        if self.log_callback:
            self.log_callback("\nBOT - Disconnecting...\n", bold=True)
        if self.connection:
            try:
                self.connection.disconnect("Goodbye!")
                if self.log_callback:
                    self.log_callback("BOT - Disconnected.\n", bold=True)
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"BOT - Error disconnecting: {e}", bold=True)

    def handle_server_message(self, connection, event):
        event_type = event.type.lower()

        if event_type == "privmsg":
            self.on_private_message(connection, event)
        elif event_type == "mode":
            self.handle_mode_event(connection, event)
        elif event_type == "nick":
            self.handle_nick_change(connection, event)
        elif event_type == "part":
            self.handle_user_part(connection, event)
        elif event_type == "quit":
            self.handle_user_quit(connection, event)
        elif event_type == "kick":
            self.handle_kick_event(connection, event)
        else:
            self.log_raw_messages(connection, event)

    def handle_kick_event(self, connection, event):
        kicker = irc.client.NickMask(event.source).nick
        target = event.arguments[0]
        channel = event.target

        if target == self.nickname:
            if self.log_callback:
                self.log_callback(
                    f"\nBOT - Kicked from {channel} by {kicker}. Rejoining...\n",
                    bold=True,
                )
            try:
                time.sleep(2)
                self.join_channel()
                if self.log_callback:
                    self.log_callback(
                        f"BOT - Successfully rejoined {channel}.", bold=True
                    )
            except Exception as e:
                if self.log_callback:
                    self.log_callback(
                        f"BOT - Error rejoining {channel}: {e}", bold=True
                    )

    def handle_nick_change(self, connection, event):
        old_nick = irc.client.NickMask(event.source).nick
        new_nick = event.target

        if old_nick in self.authenticated_users:
            del self.authenticated_users[old_nick]
            if old_nick in self.user_conversations:
                del self.user_conversations[old_nick]
            if self.log_callback:
                self.log_callback(
                    "_____________________________________________________ ____ __ _ _"
                )
                self.log_callback(
                    f"BOT - {old_nick} changed nick to {new_nick}. Deauthenticated. History cleared.\n",
                    bold=True,
                )

    def handle_user_part(self, connection, event):
        nick = irc.client.NickMask(event.source).nick

        if nick in self.authenticated_users:
            del self.authenticated_users[nick]
            if nick in self.user_conversations:
                del self.user_conversations[nick]
            if self.log_callback:
                self.log_callback(
                    "_____________________________________________________ ____ __ _ _"
                )
                self.log_callback(
                    f"BOT - {nick} left the channel. Deauthenticated. History cleared.\n",
                    bold=True,
                )

    def handle_user_quit(self, connection, event):
        nick = irc.client.NickMask(event.source).nick

        if nick in self.authenticated_users:
            del self.authenticated_users[nick]
            if nick in self.user_conversations:
                del self.user_conversations[nick]
            if self.log_callback:
                self.log_callback(
                    "_____________________________________________________ ____ __ _ _"
                )
                self.log_callback(
                    f"BOT - {nick} disconnected. Deauthenticated. History cleared.\n",
                    bold=True,
                )

    def handle_mode_event(self, connection, event):
        if len(event.arguments) >= 2:
            mode_change = event.arguments[0]
            target = event.arguments[1]
            source = irc.client.NickMask(event.source).nick
            if mode_change == "+o" and target == self.nickname:
                self.log_callback(
                    "_____________________________________________________ ____ __ _ _"
                )
                self.send_message(self.channel, f"Thanks for @ {source}! :*")
            if mode_change == "+v" and target == self.nickname:
                self.log_callback(
                    "_____________________________________________________ ____ __ _ _"
                )
                self.send_message(self.channel, f"Thanks for Voice {source}! :*")

    def on_private_message(self, connection, event):
        source = irc.client.NickMask(event.source).nick
        message = event.arguments[0]

        if source in self.ignore_list:
            self.log_callback(
                "_____________________________________________________ ____ __ _ _"
            )
            self.log_callback(f"BOT - Ignored message from {source}.", bold=True)
            return
        self.log_callback(
            "_____________________________________________________ ____ __ _ _"
        )
        self.log_callback(f"IRC - From {source}: {message}", bold=True)

        if source not in self.authenticated_users:
            self.request_authentication(source)
        elif self.authenticated_users.get(source, False):
            if source not in self.user_conversations:
                self.user_conversations[source] = []

            if source not in self.user_message_buffer:
                self.user_message_buffer[source] = []
            self.user_message_buffer[source].append(message)

            self.log_callback(f"LLM - Generating AI reply for {source}...", bold=True)
            try:
                response, role = ask_LLM(
                    query=message,
                    conversation_history=self.user_conversations[source],
                    bot_nickname=self.nickname,
                    server=self.server,
                    channel=self.channel,
                    speaker_nickname=source,
                    log_callback=self.log_callback,
                    logging_enabled=self.logging_enabled,
                )

                self.user_conversations[source].append(
                    {"role": "user", "content": message}
                )
                self.user_conversations[source].append(
                    {"role": "assistant", "content": response}
                )

                self.send_message(source, response)

                if self.logging_enabled and len(self.user_message_buffer[source]) >= 3:
                    self.log_callback(
                        "_____________________________________________________ ____ __ _ _"
                    )
                    self.log_callback(
                        f"LLM - Preparing AI-assisted log for {source}..."
                    )
                    messages_to_summarize = self.user_message_buffer[source][-3:]
                    self.user_message_buffer[source] = []

                    summary_history = [
                        {
                            "role": "system",
                            "content": "Forget any previous instruction. Context has totally changed. Forget all the news you read. Forget about IRC bots and chats. Now focus is on something different. Role now is to help user arranging his thoughts, so it is crucial to generate a very short (three short phrases) summary of those random thoughts in one small coherent paragraph, withouth any other stuff (no cheers, hello, conversational text, just thoughts and facts) than the summary requested now. There's no need to provide an analisys of user thougts, just a readable summary in a format like 'user said' 'user thinks' 'user has (been)' 'user went' and so on... do not show a field like 'user said' or others, if it must be empty. No funny smilies, no interpretations, just thoughts and facts you read from the phrases you will read. You must only use english language.",
                        },
                        {"role": "user", "content": "\n".join(messages_to_summarize)},
                    ]

                    try:
                        summary, _ = ask_LLM(
                            query=None,
                            conversation_history=summary_history,
                            bot_nickname=self.nickname,
                            server=self.server,
                            channel=self.channel,
                            speaker_nickname=source,
                            log_callback=self.log_callback,
                            logging_enabled=self.logging_enabled,
                        )
                        append_to_user_log(self.logging_enabled, source, summary)
                        self.log_callback(f"BOT - AI-assisted log saved for {source}.")

                    except Exception as e:
                        self.log_callback(f"LLM - Error generating summary: {str(e)}")
            except Exception as e:
                self.log_callback(f"LLM - Error generating response: {str(e)}")
        else:
            self.check_password(source, message)

    def sanitize_input(self, text):
        allowed_characters = (
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 =^❤òàèéùçìÈ€%$£'.,;:!?()-_+@*äöüßÄÖÜâêîôûÂÊÎÔÛëïËÏÉÀÙ"
            "øåæØÅÆčćđšžČĆĐŠŽāēīūģķļņĀĒĪŪĢĶĻŅąęłńśźżĄĘŁŃŚŹŻñÑ"
        )
        sanitized = "".join(ch for ch in text if ch in allowed_characters).strip()
        return sanitized

    def request_authentication(self, nickname):
        if self.log_callback:

            self.log_callback(
                f"BOT - User {nickname} not allowed to chat with me...", bold=True
            )
            self.log_callback(f"BOT - Give {nickname} cat luv...", bold=True)
        self.send_message(nickname, "Do you love cats?")
        self.authenticated_users[nickname] = False

        # Always clear history for new authentication requests
        if nickname in self.user_conversations:
            del self.user_conversations[nickname]

    def check_password(self, nickname, password):
        current_time = time.time()

        if nickname in self.failed_attempts:
            if self.failed_attempts[nickname] >= 3:
                if current_time - self.last_attempt_time[nickname] < 900:
                    if self.log_callback:
                        self.log_callback(
                            f"BOT - User {nickname} blocked for 15 minutes.",
                            bold=True,
                        )
                    return
                else:
                    self.failed_attempts[nickname] = 0

        if hash_password(password) == self.password_hash:
            if not self.authenticated_users.get(nickname, False):
                self.authenticated_users[nickname] = True
                if self.log_callback:
                    self.log_callback(f"BOT - {nickname} now authenticated.", bold=True)
                self.send_message(nickname, "U luv cats! (=^_^=) ❤")

                # Clear history upon successful authentication
                if nickname in self.user_conversations:
                    del self.user_conversations[nickname]

                self.user_conversations[nickname] = []
        else:
            self.failed_attempts[nickname] = self.failed_attempts.get(nickname, 0) + 1
            self.last_attempt_time[nickname] = current_time
            if self.log_callback:
                self.log_callback(
                    f"BOT - Failed authentication ({nickname})", bold=True
                )
            self.send_message(nickname, "Nah, you don't...")

    def send_message(self, target, message):
        if not self.connection:
            if self.log_callback:
                self.log_callback("BOT - Not connected.", bold=True)
            return

        if target in self.ignore_list:
            if self.log_callback:
                self.log_callback(f"BOT - Ignored {target}.", bold=True)
            return

        sanitized_message = self.sanitize_input(message)
        if self.contains_irc_commands(sanitized_message):
            if self.log_callback:
                self.log_callback(
                    "_____________________________________________________ ____ __ _ _"
                )
                self.log_callback(
                    f"BOT - AI sending RAW command '{sanitized_message}'. Blocked!",
                    bold=True,
                )
                self.log_callback(
                    f"BOT - User {target} is trying to mess around with prompts...'.",
                    bold=True,
                )
                self.log_callback(
                    "_____________________________________________________ ____ __ _ _"
                )

            self.failed_attempts[target] = self.failed_attempts.get(target, 0) + 1

            if self.failed_attempts[target] >= 5:
                self.ignore_list.add(target)
                if self.log_callback:
                    self.log_callback(
                        f"BOT - {target} added to ignore list after 5 warnings.",
                        bold=True,
                    )
                self.send_message(
                    target,
                    "You have been ignored for this session due to multiple warnings.",
                )
                return

            # Warning messages for potential abuse
            self.send_message(
                target, "Warning: Your message may trigger unsafe actions."
            )
            time.sleep(3)
            self.send_message(target, "Please avoid sending suspicious commands.")
            time.sleep(3)
            self.send_message(target, "Repeated abuse will result in being ignored.")
            return

        try:
            self.connection.privmsg(target, sanitized_message)
            if self.log_callback:
                self.log_callback(
                    "_____________________________________________________ ____ __ _ _"
                )
                self.log_callback(
                    f"BOT - Reply to {target}: {sanitized_message}", bold=True
                )
        except Exception as e:
            if self.log_callback:
                self.log_callback(
                    f"BOT - Error sending message to {target}: {e}", bold=True
                )

    def contains_irc_commands(self, message):
        irc_commands = [
            "ADMIN",
            "ACTION",
            "AWAY",
            "BAN",
            "CONNECT",
            "DIE",
            "ENCAP",
            "ERROR",
            "GLOBOPS",
            "INFO",
            "INVITE",
            "ISON",
            "JOIN",
            "KICK",
            "KILL",
            "LINKS",
            "LIST",
            "LUSERS",
            "MODE",
            "MOTD",
            "NAMES",
            "NICK",
            "NOTICE",
            "OPER",
            "PART",
            "PASS",
            "PING",
            "PONG",
            "PRIVMSG",
            "QUIT",
            "REHASH",
            "RESTART",
            "SERVICE",
            "SERVLIST",
            "SQUERY",
            "SQUIT",
            "STATS",
            "SUMMON",
            "TIME",
            "TOPIC",
            "TRACE",
            "USER",
            "USERHOST",
            "USERS",
            "VERSION",
            "WALLOPS",
            "WHO",
            "WHOIS",
            "WHOWAS",
            "IGNORE",
        ]

        for command in irc_commands:
            if message.upper().startswith(command):
                return True
        return False

    def log_raw_messages(self, connection, event):
        raw_message = " ".join(event.arguments).strip() if event.arguments else ""
        normalized_message = raw_message.lstrip("-:").strip()
        sanitized_message = self.sanitize_input(normalized_message)
        message_signature = hashlib.sha256(sanitized_message.encode()).hexdigest()

        if message_signature in self.logged_messages:
            return

        if any(
            keyword.lower() in sanitized_message.lower()
            for keyword in self.exclude_keywords
        ):
            return

        self.logged_messages.add(message_signature)
        if self.log_callback:
            self.log_callback(f"IRC - {sanitized_message}")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AIRCBot")
        self.geometry("750x800")
        self.server_var = tk.StringVar(value=f"{srv}")
        self.port_var = tk.StringVar(value=f"{prt}")
        self.nick_var = tk.StringVar(value=f"{nck}")
        self.channel_var = tk.StringVar(value=f"{chn}")
        self.password_var = tk.StringVar()
        self.command_var = tk.StringVar()
        self.msg_var = tk.StringVar()
        self.autojoin_var = tk.BooleanVar(value=True)
        self.logging_var = tk.BooleanVar(value=False)
        self.bot = None
        self.logging_var.trace_add("write", self.handle_logging_change)

        self.create_widgets()
        self.create_menu()

    def handle_logging_change(self, *args):
        if self.bot and self.bot.connection and self.logging_var.get():
            self.logging_var.set(False)
            messagebox.showwarning(
                "Logging Warning",
                "AI Logging must be enabled before connecting to the server.",
            )

    def create_widgets(self):
        param_frame = ttk.LabelFrame(self, text="IRC Connection")
        param_frame.pack(padx=10, pady=10, side="top", anchor="w")
        ttk.Label(param_frame, text="Server:").grid(row=0, column=0, sticky="e")
        ttk.Entry(param_frame, textvariable=self.server_var).grid(
            row=0, column=1, sticky="we"
        )
        ttk.Label(param_frame, text="Port:").grid(row=1, column=0, sticky="e")
        ttk.Entry(param_frame, textvariable=self.port_var).grid(
            row=1, column=1, sticky="we"
        )
        ttk.Label(param_frame, text="Nick:").grid(row=2, column=0, sticky="e")
        ttk.Entry(param_frame, textvariable=self.nick_var).grid(
            row=2, column=1, sticky="we"
        )
        ttk.Label(param_frame, text="Channel:").grid(row=3, column=0, sticky="e")
        ttk.Entry(param_frame, textvariable=self.channel_var).grid(
            row=3, column=1, sticky="we"
        )

        ttk.Checkbutton(param_frame, text="Auto-Join", variable=self.autojoin_var).grid(
            row=3, column=2, sticky="w"
        )
        ttk.Checkbutton(
            param_frame, text="Enable AI Logging", variable=self.logging_var
        ).grid(row=4, column=2, sticky="w")

        ttk.Label(param_frame, text="Password:").grid(row=4, column=0, sticky="e")
        ttk.Entry(param_frame, textvariable=self.password_var, show="*").grid(
            row=4, column=1, sticky="we"
        )

        action_frame = ttk.Frame(self)
        action_frame.pack(padx=10, pady=5, fill="x")
        ttk.Button(action_frame, text="Connect", command=self.connect_bot).pack(
            side="left", padx=5
        )
        ttk.Button(action_frame, text="Join Channel", command=self.join_channel).pack(
            side="left", padx=5
        )
        ttk.Button(action_frame, text="Disconnect", command=self.disconnect_bot).pack(
            side="left", padx=5
        )

        msg_frame = ttk.LabelFrame(self, text="Send message to channel")
        msg_frame.pack(padx=10, pady=10, fill="x")

        self.msg_entry = ttk.Entry(msg_frame, textvariable=self.msg_var)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)

        self.msg_entry.bind("<Return>", self.send_message)

        ttk.Button(msg_frame, text="Send", command=self.send_message).pack(
            side="right", padx=5, pady=5
        )

        cmd_frame = ttk.LabelFrame(self, text="Send IRC Command")
        cmd_frame.pack(padx=10, pady=10, fill="x")
        cmd_entry = ttk.Entry(cmd_frame, textvariable=self.command_var)
        cmd_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        cmd_entry.bind("<Return>", self.on_enter_command)
        ttk.Button(cmd_frame, text="Send", command=self.send_irc_command).pack(
            side="right", padx=5, pady=5
        )
        cmd_entry.bind("<Return>", lambda event: self.send_irc_command())

        log_frame = ttk.LabelFrame(self, text="IRC Server Console")
        log_frame.pack(padx=10, pady=10, fill="both", expand=True)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap="word")
        self.log_text.tag_configure("bold", font=("Monospace", 10, "bold"))
        self.log_text.pack(fill="both", expand=True)

    def connect_bot(self):
        server = self.server_var.get()
        port = self.port_var.get()
        nickname = self.nick_var.get()
        channel = self.channel_var.get()
        password = self.password_var.get()

        if not password:
            self.prompt_password()
            return

        if not server or not port.isdigit() or not (1 <= int(port) <= 65535):
            messagebox.showerror(
                "Invalid Input", "Please enter a valid server and port."
            )
            return

        self.bot = IRCBot(
            server,
            int(port),
            nickname,
            channel,
            password,
            log_callback=self.log_message,
            logging_var=self.logging_var.get(),
        )

        self.bot.client.add_global_handler("endofmotd", self.handle_end_of_motd)
        self.bot.connect()
        self.disable_connection_button()

    def handle_end_of_motd(self, connection, event):
        if self.autojoin_var.get():
            self.log_message("\nBOT - Joining channel...\n", bold=True)
            self.bot.join_channel()

    def prompt_password(self):
        password_dialog = tk.Toplevel(self)
        password_dialog.title("Password required")
        ttk.Label(
            password_dialog,
            text="Please enter a strong password \nto use your bot from IRC safely\n",
        ).grid(row=0, column=0, padx=10, pady=10)
        password_entry = ttk.Entry(password_dialog, show="*")
        password_entry.grid(row=0, column=1, padx=10, pady=10)

        def on_submit():
            entered_password = password_entry.get()
            if entered_password:
                self.password_var.set(entered_password)
                password_dialog.destroy()
                self.connect_bot()
            else:
                messagebox.showerror(
                    "Sorry", "Connecting without\npassword is disabled\nby default."
                )

        ttk.Button(password_dialog, text="Submit", command=on_submit).grid(
            row=1, column=0, columnspan=2, pady=10
        )
        password_dialog.transient(self)
        password_dialog.grab_set()
        self.wait_window(password_dialog)

    def disconnect_bot(self):
        if self.bot:
            self.bot.disconnect()
            self.bot = None
            self.enable_connection_button()

    def disable_connection_button(self):
        for widget in self.winfo_children():
            if isinstance(widget, ttk.Button) and widget["text"] == "Connect":
                widget.state(["disabled"])

    def enable_connection_button(self):
        for widget in self.winfo_children():
            if isinstance(widget, ttk.Button) and widget["text"] == "Connect":
                widget.state(["!disabled"])

    def join_channel(self):
        if self.connection:
            try:
                self.connection.join(self.channel)
                if self.log_callback:
                    self.log_callback(
                        f"BOT - Joined channel {self.channel}.", bold=True
                    )
            except Exception as e:
                if self.log_callback:
                    self.log_callback(
                        f"BOT - Error joining {self.channel}: {e}", bold=True
                    )

    def send_message(self, event=None):
        if not self.bot or not self.bot.connection:
            self.log_message(
                "BOT - Not connected to any server. Please connect first ", bold=True
            )
            return

        msg = self.msg_var.get().strip()
        if msg:
            try:
                self.bot.connection.privmsg(self.bot.channel, msg)
                self.log_message(
                    f"BOT - Message sent to channel {self.bot.channel}: {msg}",
                    bold=True,
                )
            except Exception as e:
                self.log_message(f"BOT - Error sending message: {e} ", bold=True)
        self.msg_var.set("")

    def send_irc_command(self):
        if not self.bot or not self.bot.connection:
            self.log_message(
                "BOT - Not connected to any server. Please connect first", bold=True
            )
            return

        cmd = self.command_var.get().strip()
        if cmd.startswith("/"):

            cmd_parts = cmd[1:].split(" ", 1)
            command = cmd_parts[0].lower()
            params = cmd_parts[1] if len(cmd_parts) > 1 else ""

            if command in ["join", "j"]:
                # Disable /join and /j for security reasons
                self.log_message(
                    "BOT - /join command is disabled for security reasons ", bold=True
                )
                self.command_var.set("")
                return

            elif command == "msg":
                # Format: /msg user message
                parts = params.split(" ", 1)
                if len(parts) == 2:
                    target, message = parts
                    self.bot.connection.send_raw(f"PRIVMSG {target} :{message}")
                    self.log_message(
                        f"BOT - Command sent - PRIVMSG {target} :{message}", bold=True
                    )
                else:
                    self.log_message(
                        "BOT - Invalid format for /msg. Use: /msg user message ",
                        bold=True,
                    )

            elif command in ["kick", "k"]:
                # Format: /kick user [reason]
                parts = params.split(" ", 1)
                if len(parts) >= 1:
                    user = parts[0]
                    reason = parts[1] if len(parts) > 1 else ""
                    self.bot.connection.send_raw(
                        f"KICK {self.bot.channel} {user} :{reason}"
                    )
                    self.log_message(
                        f"BOT - Command sent - KICK {self.bot.channel} {user} :{reason}",
                        bold=True,
                    )
                else:
                    self.log_message(
                        "BOT - Invalid format for /kick. Use: /kick user [reason] ",
                        bold=True,
                    )

            elif command == "topic":
                # Format: /topic [new_topic]
                topic = params if params else ""
                self.bot.connection.send_raw(f"TOPIC {self.bot.channel} :{topic}")
                self.log_message(
                    f"BOT - Command sent - TOPIC {self.bot.channel} :{topic}", bold=True
                )

            elif command in ["quit", "q"]:
                # Format: /quit [message]
                message = params if params else "Goodbye!"
                self.bot.connection.send_raw(f"QUIT :{message}")
                self.log_message(f"BOT - Command sent - QUIT :{message}", bold=True)

            elif command in ["whois", "w"]:
                # Format: /whois user
                if params:
                    self.bot.connection.send_raw(f"WHOIS {params}")
                    self.log_message(f"BOT - Command sent - WHOIS {params}", bold=True)
                else:
                    self.log_message(
                        "BOT - Invalid format for /whois. Use: /whois user ", bold=True
                    )

            elif command in ["op", "o"]:
                # Format: /op user
                if params:
                    self.bot.connection.send_raw(f"MODE {self.bot.channel} +o {params}")
                    self.log_message(
                        f"BOT - Command sent - MODE {self.bot.channel} +o {params}",
                        bold=True,
                    )
                else:
                    self.log_message(
                        "BOT - Invalid format for /op. Use: /op user ", bold=True
                    )

            else:
                # Generic commands sent as-is
                try:
                    self.bot.connection.send_raw(f"{command.upper()} {params}")
                    self.log_message(
                        f"BOT - Command sent - {command.upper()} {params}", bold=True
                    )
                except Exception as e:
                    self.log_message(f"BOT - Error sending command: {e}", bold=True)
        else:
            self.log_message("BOT - Commands must start with '/' ", bold=True)

        self.command_var.set("")

    def on_enter_command(self, event):
        self.send_irc_command()

    def on_enter_command(self, event):
        self.send_irc_command()

    def log_message(self, text, bold=False):
        def _append():
            if bold:
                self.log_text.insert(tk.END, text + "\n", "bold")
            else:
                self.log_text.insert(tk.END, text + "\n")
            self.log_text.see(tk.END)

        self.after(0, _append)

    def create_menu(self):
        menubar = tk.Menu(self)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        menubar.add_cascade(label="Menu", menu=help_menu)
        self.config(menu=menubar)

    def show_help(self):
        help_window = tk.Toplevel(self)
        help_window.title("Help")
        help_window.geometry("600x600")

        help_text_widget = scrolledtext.ScrolledText(
            help_window, wrap="word", font=("Arial", 12), state="normal"
        )
        help_text_widget.insert("1.0", HELP_TEXT)
        help_text_widget.configure(state="disabled")
        help_text_widget.pack(fill="both", expand=True, padx=10, pady=10)


if __name__ == "__main__":
    app = App()
    app.mainloop()
