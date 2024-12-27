import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext, messagebox
import socket
import threading
import requests
import feedparser
from datetime import datetime
import time
import hashlib
import random

# Customize with your favourite feed
FEED_URL = "https://www.ansa.it/english/news/english_nr_rss.xml"

# Default options at startup (user can modify them via UI)
nck = "Egidio"  # Nick
srv = "openirc.snt.utwente.nl"  # Server
prt = "6667"  # Port
chn = "#casale"  # Channel
usr = "aipwrd"


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def fetch_news_from_feed(max_items=3):
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
- Personal preferences: you love cats

Latest news: {news_section}. Remember them in case the conversation is about current events.

Follow IRC netiquette and slang: be concise, polite, add a touch of friendliness with emoticons like :)
Be friendly and sociable with everyone, but always be concise.
Don't introduce yourself as an assistant, but as a curious person who suggests conversation topics,
who wants to share thoughts like a human being. It's crucial that you always respond in the language questions are made with, without errors and just one line plain text without formatting it with enter characters, paragraphs and so on.
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

    system_idx = next(
        (i for i, m in enumerate(conversation_history) if m["role"] == "system"), None
    )
    if system_idx is not None:
        conversation_history[system_idx]["content"] = system_prompt
    else:
        conversation_history.insert(0, {"role": "system", "content": system_prompt})

    conversation_history.append({"role": "user", "content": query})
    limited_history = conversation_history[-20:]

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
        self.password_hash = hash_password(password)
        self.socket = None
        self.stop_thread = False
        self.conversation_history = []
        self.log_callback = log_callback
        self.authenticated_users = {}
        self.failed_attempts = {}
        self.last_attempt_time = {}

    def keep_alive(self):
        while not self.stop_thread:
            time.sleep(60)
            self.send_command(f"PING {self.server}")
            self.log("--> Staying alive... Staying alive...\n")


    def connect(self):
        self.log(f"--> Attempting connection to {self.server}:{self.port}...")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(60)
            self.socket.connect((self.server, self.port))
            self.log(f"--> Successfully connected to {self.server}:{self.port}!\n")
            self.send_command(f"NICK {self.nickname}")
            self.send_command(f"USER {usr} 0 * :{self.nickname}")
            self.log(f"\n--> {self.server} is checking our connection, be patient...\n")

            self.stop_thread = False
            self.listen_thread = threading.Thread(
                target=self.listen_to_server, daemon=True
            )
            self.listen_thread.start()

            # Avvia il thread del "keep-alive"
            self.keep_alive_thread = threading.Thread(
                target=self.keep_alive, daemon=True
            )
            self.keep_alive_thread.start()
        except socket.timeout:
            self.log("\n!!! Connection timeout. Retrying !!!\n")
            self.disconnect()
            self.connect()
        except Exception as e:
            self.log(f"!!! Error while connecting: {e} !!!")

    def disconnect(self):
        self.log("--> Disconnecting...")
        self.stop_thread = True
        if self.socket:
            try:
                self.socket.close()
                self.log("--> Disconnected.")
            except Exception as e:
                self.log(f"!!! Error disconnecting: {e} !!!")
        self.socket = None

    def join_channel(self):
        if self.channel:
            self.send_command(f"JOIN {self.channel}")

    def send_message(self, target: str, msg: str):
        irc_msg = f"PRIVMSG {target} :{msg}"
        self.send_command(irc_msg)

    def send_command(self, raw_cmd: str):
        if self.socket and raw_cmd:
            self.log(f"--> {raw_cmd}")
            try:
                self.socket.sendall((raw_cmd + "\r\n").encode("utf-8"))
            except Exception as e:
                self.log(f"!!! Error sending command: {e} !!!")

    def listen_to_server(self):
        buffer = ""
        while not self.stop_thread:
            try:
                data = self.socket.recv(2048).decode("utf-8", errors="ignore")
                if not data:
                    self.log("!!! Connection lost !!!")
                    break
                buffer += data
                if "PING" in data:
                    pong_token = data.split()[1]
                    self.send_command(f"PONG {pong_token}")
                    self.log("--> Connection verified!\n")


                    self.log(f"--> {nck} is now ready to chat!\n")

                lines = buffer.split("\r\n")
                buffer = lines.pop()
                for line in lines:
                    if any(
                        code in line
                        for code in [
                            "001",
                            "020",
                            "002",
                            "003",
                            "004",
                            "005",
                            "042",
                            "252",
                            "253",
                            "254",
                            "255",
                            "256",
                            "265",
                            "375",
                            "372",
                            "376",
                            "251",
                            "266",
                        ]
                    ):
                        continue
                    self.log(f"{line}")
                    if "ERROR" in line:
                        self.log("!!! Command rejected by server: " + line)
                    self.handle_irc_line(line)
            except Exception as e:
                self.log(f"!!! Error listening to server: {e} !!!")
                break

    def handle_irc_line(self, line: str):
        if "MODE" in line and f"+o {self.nickname}" in line:
            # Identifica il nome del canale
            parts = line.split()
            if len(parts) > 2 and parts[2].startswith("#"):
                channel = parts[2]
                # Ringrazia pubblicamente sul canale
                self.send_message(
                    channel, "Grazie per l'OP! :)"
                )
                self.log(f"--> Sent thank-you message to {channel}.")
            return

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

            if target == self.channel:
                return
            else:
                if nickname_src not in self.authenticated_users:
                    self.request_authentication(nickname_src)
                elif self.authenticated_users[nickname_src]:
                    try:
                        self.log(
                            f"\n--> Generating AI response for {nickname_src}...\n"
                        )
                        risposta_ai, role = ask_gpt4(
                            query=user_message,
                            conversation_history=self.conversation_history,
                            bot_nickname=self.nickname,
                            server=self.server,
                            channel=self.channel,
                            speaker_nickname=nickname_src,
                        )
                        self.send_message(nickname_src, risposta_ai)
                    except Exception as e:
                        risposta_ai = f"[AI Error] {e}"
                        self.log(f"!!! Error generating AI response: {e} !!!")
                        self.send_message(nickname_src, risposta_ai)
                else:
                    self.check_password(nickname_src, user_message)

                    
    def request_authentication(self, nickname):
        self.log(f"\n!!! Auth requested from {nickname} checking if he loves cats !!!\n")
        self.send_message(nickname, "Do you love cats?")
        self.authenticated_users[nickname] = False

    def check_password(self, nickname, password):
        current_time = time.time()
        if nickname in self.failed_attempts:
            if self.failed_attempts[nickname] >= 3:
                if current_time - self.last_attempt_time[nickname] < 120:
                    self.log(f"!!! User {nickname} is a cat hater and temporarily blocked !!!")
                    return
                else:
                    self.failed_attempts[nickname] = 0

        if hash_password(password) == self.password_hash:
            self.authenticated_users[nickname] = True
            self.failed_attempts[nickname] = 0
            self.log(f"\n!!! User {nickname} authenticated !!!\n")
            self.send_message(nickname, "Ok, say something...")
        else:
            self.failed_attempts[nickname] = self.failed_attempts.get(nickname, 0) + 1
            self.last_attempt_time[nickname] = current_time
            self.log(f"!!! Failed authentication by cat hater {nickname} !!!")
            
            # Lista di frasi casuali
            phrases = [
                "Meow... (=ㅇㅅㅇ=)",
                "Nah... (=￣ω￣=)",
                "Grrr.... (=ↀωↀ=)",
                "I love cats. (=♡‿♡=)",
                "No way. FFFT! (=`ω´=)"
            ]
            chosen_phrase = random.choice(phrases)
            self.send_message(nickname, chosen_phrase)

    def log(self, text: str):
        if self.log_callback:
            self.log_callback(text)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AIRCBot")

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
        server_entry = ttk.Entry(param_frame, textvariable=self.server_var)
        server_entry.grid(row=0, column=1, sticky="we", padx=5, pady=5)

        ttk.Label(param_frame, text="Port:").grid(
            row=1, column=0, sticky="e", padx=5, pady=5
        )
        port_entry = ttk.Entry(param_frame, textvariable=self.port_var)
        port_entry.grid(row=1, column=1, sticky="we", padx=5, pady=5)

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
            "1. Send message: Enter a message in the text field and press Send button to send it to current channel, like with a regular IRC client.\n"
            '2. Send Command: Enter a raw IRC command (e.g., "WHO", "MODE") in the field and press Enter or Send button to send it.\n\n'
            "** Console **\n"
            "1. Console logs all bot activities: connections, commands sent, messages received, etc.\n"
            "2. Use the console to monitor bot's interaction with IRC server.\n\n"
            "** Authentication **\n"
            "1. If a user sends a direct message to the bot, authentication with a password is requested.\n"
            "2. User has three attempts to authenticate before being temporarily blocked for 120 seconds to discourage brute force.\n"
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
        port = self.port_var.get()
        nickname = self.nick_var.get()
        channel = self.channel_var.get()
        password = self.password_var.get()

        if not password:
            # Mostra un popup per richiedere la password
            password_dialog = tk.Toplevel(self)
            password_dialog.title("Password needed")
            ttk.Label(password_dialog, text="Password field is empty!\nEnter your password now\nto access your bot via IRC.").grid(row=0, column=0, padx=10, pady=10)
            password_entry = ttk.Entry(password_dialog, show="*")
            password_entry.grid(row=0, column=1, padx=10, pady=10)

            def on_password_submit():
                new_password = password_entry.get()
                if new_password:
                    self.password_var.set(new_password)  # Aggiorna il campo password
                    password_dialog.destroy()  # Chiude il popup
                    self.connect_bot()  # Riprova la connessione
                else:
                    messagebox.showerror("Errore", "La password non può essere vuota!")

            submit_button = ttk.Button(password_dialog, text="Connect", command=on_password_submit)
            submit_button.grid(row=1, column=0, columnspan=2, pady=10)

            password_dialog.transient(self)
            password_dialog.grab_set()
            self.wait_window(password_dialog)
            return

        if not server or not port.isdigit() or not (1 <= int(port) <= 65535):
            messagebox.showerror(
                "Input non valido", "Inserisci un server e una porta validi."
            )
            return

        self.bot = IRCBot(
            server,
            int(port),
            nickname,
            channel,
            password,
            log_callback=self.log_message,
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
                self.log_message(
                    "!!! /join command is disabled and cannot be executed !!!"
                )
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
