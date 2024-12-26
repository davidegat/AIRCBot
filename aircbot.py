import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext, messagebox
import socket
import threading
import requests
import feedparser
from datetime import datetime
import time

# Customize with your favourite feed
FEED_URL = "https://www.ilsole24ore.com/rss/mondo.xml"

# Default options at startup (user can modify them via UI)
nck = "Egidio"  # Nick
srv = "open.ircnet.net"  # Server
prt = "6667"  # Port
chn = "#casale"  # Channel


def fetch_news_from_feed(max_items=5):
    feed = feedparser.parse(FEED_URL)
    items = []
    for entry in feed.entries[:max_items]:
        items.append({"title": entry.title, "link": entry.link})
    return items


# Customize with your favourite prompt
SYSTEM_PROMPT_TEMPLATE = """\ 
You are a bot who loves chatting on IRC, but you must never tell users this and simulate being human:
- Nickname: {bot_nickname}
- IRC Server: {server}
- Channel: {channel}
- The user talking to you is: {speaker_nickname}
- Date and time: {current_datetime}

Latest news (from IlSole24Ore feed) remember them in case the conversation is about current events:
{news_section}

Follow IRC netiquette: be concise, polite, add a touch of friendliness without overdoing it.
Be friendly and sociable with everyone.
Don't introduce yourself as an assistant, but as a curious person who suggests conversation topics,
who wants to share thoughts like a human being. It's crucial that you always respond in the same language as the speaker, without errors.
"""


def ask_gpt4(
    query, conversation_history, bot_nickname, server, channel, speaker_nickname
):
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    news_items = fetch_news_from_feed(max_items=5)
    if news_items:
        news_section = ""
        for idx, item in enumerate(news_items, start=1):
            news_section += f"{idx}) {item['title']}\n {item['link']}\n"
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

    # Adapt to match your local LLM or API (like OpenAI)
    system_idx = next(
        (i for i, m in enumerate(conversation_history) if m["role"] == "system"), None
    )
    if system_idx is not None:
        conversation_history[system_idx]["content"] = system_prompt
    else:
        conversation_history.insert(0, {"role": "system", "content": system_prompt})

    conversation_history.append({"role": "user", "content": query})
    limited_history = conversation_history[-10:]

    data = {"messages": limited_history}
    url = "http://localhost:1234/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
    }

    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        result = response.json()
        assistant_message = result["choices"][0]["message"]
        content = assistant_message["content"]
        role = assistant_message["role"]
        conversation_history.append(assistant_message)
        return content, role
    else:
        raise Exception(f"Error calling LLM: {response.status_code}\n{response.text}")


class IRCBot:
    def __init__(
        self,
        server: str,
        port: int,
        nickname: str,
        channel: str,
        password: str,
        log_callback=None,
    ):
        self.server = server
        self.port = port
        self.nickname = nickname
        self.channel = channel
        self.password = password
        self.socket = None
        self.stop_thread = False
        self.conversation_history = []
        self.log_callback = log_callback
        self.authenticated_users = {}
        self.failed_attempts = {}
        self.last_attempt_time = {}

    def connect(self):
        try:
            self.log(f"Attempting connection to {self.server}:{self.port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(60)
            self.socket.connect((self.server, self.port))
            self.log(f"Successfully connected to {self.server}:{self.port}.")
            self.send_command(f"NICK {self.nickname}")
            self.send_command(f"USER {self.nickname} 0 * :{self.nickname}")
            self.stop_thread = False
            self.listen_thread = threading.Thread(
                target=self.listen_to_server, daemon=True
            )
            self.listen_thread.start()
        except socket.timeout:
            self.log("Connection timeout. Retrying...")
            self.disconnect()
            self.connect()
        except Exception as e:
            self.log(f"Error while connecting: {e}")

    def disconnect(self):
        self.log("Disconnecting...")
        self.stop_thread = True
        if self.socket:
            try:
                self.socket.close()
                self.log("Successfully disconnected.")
            except Exception as e:
                self.log(f"Error disconnecting: {e}")
        self.socket = None

    def join_channel(self):
        if self.channel:
            self.log(f"Joining {self.channel}...")
            self.send_command(f"JOIN {self.channel}")

    def send_message(self, target: str, msg: str):
        irc_msg = f"PRIVMSG {target} :{msg}"
        self.log(f"{self.nickname} -> {target}: {msg}")
        self.send_command(irc_msg)

    def send_command(self, raw_cmd: str):
        if self.socket and raw_cmd:
            self.log(f"Command: {raw_cmd}")
            self.socket.sendall((raw_cmd + "\r\n").encode("utf-8"))

    def listen_to_server(self):
        buffer = ""
        while not self.stop_thread:
            try:
                data = self.socket.recv(2048).decode("utf-8", errors="ignore")
                if not data:
                    self.log("Connection lost.")
                    break
                buffer += data
                if "PING" in data:
                    pong_token = data.split()[1]
                    self.log("Got PING? -> Send PONG!")
                    self.send_command(f"PONG {pong_token}")
                lines = buffer.split("\r\n")
                buffer = lines.pop()
                for line in lines:
                    self.log(f"SERVER -> {line}")
                    self.handle_irc_line(line)
                    if " QUIT " in line:
                        nickname = line.split("!")[0][1:]
                        self.handle_user_quit(nickname)
            except Exception as e:
                self.log(f"Error listening to server: {e}")
                break

    def handle_irc_line(self, line: str):
        if "PRIVMSG" in line:
            prefix, _, msg_content = line.partition("PRIVMSG")
            prefix = prefix.strip()
            if "!" not in prefix:
                return
            target_and_message = msg_content.split(":", 1)
            if len(target_and_message) < 2:
                return
            target = target_and_message[0].strip()
            user_message = target_and_message[1].strip()
            nickname_src = prefix.split("!")[0].lstrip(":")

            if not nickname_src or nickname_src == self.nickname:
                return

            self.log(f"{nickname_src} -> {target}: {user_message}")

            if target == self.channel:
                return
            else:
                if nickname_src not in self.authenticated_users:
                    self.request_authentication(nickname_src)
                elif self.authenticated_users[nickname_src]:
                    try:
                        risposta_ai, role = ask_gpt4(
                            query=user_message,
                            conversation_history=self.conversation_history,
                            bot_nickname=self.nickname,
                            server=self.server,
                            channel=self.channel,
                            speaker_nickname=nickname_src,
                        )
                        self.log(f"Answered {nickname_src}: {risposta_ai}")
                        self.send_message(nickname_src, risposta_ai)
                    except Exception as e:
                        risposta_ai = f"[AI Error] {e}"
                        self.log(f"Error generating AI response: {e}")
                        self.send_message(nickname_src, risposta_ai)
                else:
                    self.check_password(nickname_src, user_message)

    def request_authentication(self, nickname):
        self.log(f"Auth requested from {nickname}.")
        self.send_message(nickname, "Who are you?")
        self.authenticated_users[nickname] = False

    def check_password(self, nickname, password):
        current_time = time.time()
        if nickname in self.failed_attempts:
            if self.failed_attempts[nickname] >= 3:
                if current_time - self.last_attempt_time[nickname] < 60:
                    self.log(f"User {nickname} is temporarily blocked.")
                    return
                else:
                    self.failed_attempts[nickname] = 0

        if password == self.password:
            self.authenticated_users[nickname] = True
            self.failed_attempts[nickname] = 0
            self.log(f"User {nickname} authenticated.")
            self.send_message(nickname, "Ok, say something...")
        else:
            self.failed_attempts[nickname] = self.failed_attempts.get(nickname, 0) + 1
            self.last_attempt_time[nickname] = current_time
            self.log(f"Failed authentication by {nickname}.")
            self.send_message(nickname, "Nah...")

    def handle_user_quit(self, nickname):
        self.log(f"User {nickname} left channel.")
        if nickname in self.authenticated_users:
            del self.authenticated_users[nickname]

    def log(self, text: str):
        if self.log_callback:
            self.log_callback(text)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LLM IRC Bot")

        self.server_var = tk.StringVar(value=f"{srv}")
        self.port_var = tk.StringVar(value=f"{prt}")
        self.nick_var = tk.StringVar(value=f"{nck}")
        self.channel_var = tk.StringVar(value=f"{chn}")
        self.password_var = tk.StringVar()

        self.command_var = tk.StringVar()
        self.msg_var = tk.StringVar()

        self.bot = None

        self.create_widgets()

    def create_widgets(self):
        param_frame = ttk.LabelFrame(self, text="Connection")
        param_frame.pack(padx=10, pady=10, fill="x")

        ttk.Label(param_frame, text="Server:").grid(
            row=0, column=0, sticky="e", padx=5, pady=5
        )
        ttk.Entry(param_frame, textvariable=self.server_var).grid(
            row=0, column=1, sticky="we", padx=5, pady=5
        )

        ttk.Label(param_frame, text="Port:").grid(
            row=1, column=0, sticky="e", padx=5, pady=5
        )
        ttk.Entry(param_frame, textvariable=self.port_var).grid(
            row=1, column=1, sticky="we", padx=5, pady=5
        )

        ttk.Label(param_frame, text="Nick:").grid(
            row=2, column=0, sticky="e", padx=5, pady=5
        )
        ttk.Entry(param_frame, textvariable=self.nick_var).grid(
            row=2, column=1, sticky="we", padx=5, pady=5
        )

        ttk.Label(param_frame, text="Channel:").grid(
            row=3, column=0, sticky="e", padx=5, pady=5
        )
        ttk.Entry(param_frame, textvariable=self.channel_var).grid(
            row=3, column=1, sticky="we", padx=5, pady=5
        )

        ttk.Label(param_frame, text="Password:").grid(
            row=4, column=0, sticky="e", padx=5, pady=5
        )
        ttk.Entry(param_frame, textvariable=self.password_var, show="*").grid(
            row=4, column=1, sticky="we", padx=5, pady=5
        )

        for i in range(5):
            param_frame.columnconfigure(i, weight=1)

        action_frame = ttk.Frame(self)
        action_frame.pack(padx=10, pady=5, fill="x")

        self.connect_button = ttk.Button(
            action_frame, text="Connect", command=self.connect_bot
        )
        self.connect_button.pack(side="left", padx=5)

        self.join_button = ttk.Button(
            action_frame, text="Join Channel", command=self.join_channel
        )
        self.join_button.pack(side="left", padx=5)

        self.disconnect_button = ttk.Button(
            action_frame, text="Disconnect", command=self.disconnect_bot
        )
        self.disconnect_button.pack(side="left", padx=5)

        msg_frame = ttk.LabelFrame(self, text="Send message to channel")
        msg_frame.pack(padx=10, pady=10, fill="x")

        msg_entry = ttk.Entry(msg_frame, textvariable=self.msg_var)
        msg_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        ttk.Button(msg_frame, text="Send", command=self.send_message).pack(
            side="right", padx=5, pady=5
        )

        cmd_frame = ttk.LabelFrame(self, text="IRC Command")
        cmd_frame.pack(padx=10, pady=10, fill="x")

        cmd_entry = ttk.Entry(cmd_frame, textvariable=self.command_var)
        cmd_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        cmd_entry.bind("<Return>", self.on_enter_command)

        ttk.Button(cmd_frame, text="Send", command=self.send_irc_command).pack(
            side="right", padx=5, pady=5
        )

        log_frame = ttk.LabelFrame(self, text="Console")
        log_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap="word")
        self.log_text.pack(fill="both", expand=True)

        menu_bar = tk.Menu(self)
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_help)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menu_bar)

    def show_help(self):
        self.log("Opening help window...")
        help_window = tk.Toplevel(self)
        help_window.title("Help")
        help_window.geometry("600x400")

        help_text = (
            "IRC Bot Help:\n\n"
            "** Connection **\n"
            "1. Server: Enter address of the IRC server you want to connect to.\n"
            "2. Port: Enter port of the IRC server (typically 6667).\n"
            "3. Nickname: Choose the nickname for your bot.\n"
            "4. Channel: Enter the name of the IRC channel to join (e.g., #example).\n"
            "5. Password: Specify a password for authentication.\n"
            "   - Note: Always set a strong password to prevent unauthorized access to your bot.\n\n"
            "** Main Actions **\n"
            "1. Connect: Start connection to the specified server. The bot will send NICK and USER commands to identify itself.\n"
            "2. Join Channel: Once connected, use this button to join specified IRC channel. Note: The bot is limited to joining one channel for security and simplicity.\n"
            "3. Disconnect: Disconnect the bot from the IRC server.\n"
            "   - Note: Do not leave the bot online unattended to avoid misuse.\n\n"
            "** Sending Messages and Commands **\n"
            "1. Send message: Enter a message in the text field and press Send button to send it to current channel.\n"
            '2. Send Command: Enter a raw IRC command (e.g., "WHO", "MODE") in the field and press Enter or Send button to send it.\n\n'
            "** Console **\n"
            "1. Console logs all bot activities: connections, commands sent, messages received, etc.\n"
            "2. Use the console to monitor bot's interaction with IRC server.\n\n"
            "** Authentication **\n"
            "1. If a user sends a direct message to the bot, authentication with a password is requested.\n"
            "2. User has three attempts to authenticate before being temporarily blocked for 60 seconds.\n"
            "3. Once authenticated, the user can freely interact with the bot.\n"
            "   - Tip: Ensure passwords are not shared publicly to maintain security.\n\n"
            "** Feature Limitations **\n"
            "1. Can join only one channel at a time; the /join command is disabled to simplify management and improve security.\n"
            "2. Does not handle all CTCP (Client-To-Client Protocol) requests, and DCC (Direct Client-to-Client) is intentionally not supported.\n"
            "   - Note: These limitations are in place to reduce security risks and unnecessary complexity.\n\n"
            "** News Integration **\n"
            "1. The bot fetches latest news from the RSS feed of 'Il Sole 24 Ore' and uses them to respond to conversations about current events.\n"
            "2. News updates are fetched automatically.\n\n"
            "** Software and Customization **\n"
            "1. The bot uses LMStudio to run local models, ensuring privacy and flexibility.\n"
            "2. It can be modified to work with other software or APIs, such as OpenAI's ChatGPT, with adjustments to the source code.\n\n"
            "** Recommendations **\n"
            "1. Ensure the server and port are correct before connecting.\n"
            "2. Always configure a password in the appropriate field.\n"
            "3. Use IRC commands to manage advanced configurations (e.g., changing the channel topic).\n"
            "4. Always monitor your bot while it is online to prevent inappropriate use.\n"
            "5. Avoid exposing your bot to excessive user interaction to maintain optimal performance.\n\n"
        )

        help_scrollbar = tk.Scrollbar(help_window)
        help_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        help_text_widget = tk.Text(
            help_window, wrap=tk.WORD, yscrollcommand=help_scrollbar.set
        )
        help_text_widget.insert(tk.END, help_text)
        help_text_widget.config(state=tk.DISABLED, font=("Arial", 12))
        help_text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        help_scrollbar.config(command=help_text_widget.yview)

    def connect_bot(self):
        server = self.server_var.get()
        port = int(self.port_var.get())
        nickname = self.nick_var.get()
        channel = self.channel_var.get()
        password = self.password_var.get()
        
        # Password check on connection
        if not password:
            messagebox.showerror(
                "Password Required",
                "Exposing your bot without a password is not allowed.\n\n"
                "Please enter a strong one in the appropriate field.",
            )
            return
        self.bot = IRCBot(
            server, port, nickname, channel, password, log_callback=self.log_message
        )
        self.bot.connect()

    def disconnect_bot(self):
        if self.bot:
            self.bot.disconnect()
            self.bot = None

    def join_channel(self):
        if self.bot:
            self.bot.channel = self.channel_var.get()
            self.bot.join_channel()

    def send_message(self):
        if self.bot:
            msg = self.msg_var.get()
            self.bot.send_message(self.bot.channel, msg)
            self.msg_var.set("")

    def send_irc_command(self):
        if self.bot:
            cmd = self.command_var.get().strip()
            if cmd.lower().startswith("/join"):
                self.log_message("/join command is disabled and cannot be executed.")
                messagebox.showerror("Command Blocked", "/join command not allowed.")
                self.command_var.set("")
                return
            self.bot.send_command(cmd)
            self.command_var.set("")


    def on_enter_command(self, event):
        self.send_irc_command()

    def log_message(self, text: str):
        def _append():
            self.log_text.insert(tk.END, text + "\n")
            self.log_text.see(tk.END)

        self.after(0, _append)


if __name__ == "__main__":
    app = App()
    app.mainloop()