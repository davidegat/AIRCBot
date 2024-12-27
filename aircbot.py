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


class IRCBot:
    def __init__(self, server, port, nickname, channel, password, log_callback=None):
        self.server = server
        self.port = port
        self.nickname = nickname
        self.channel = channel
        self.password_hash = hash_password(password)
        self.log_callback = log_callback
        self.authenticated_users = {}
        self.failed_attempts = {}
        self.last_attempt_time = {}
        self.client = irc.client.Reactor()
        self.connection = None
        self.keep_alive_interval = 60  # Intervallo in secondi
        self.logged_messages = set()
        self.exclude_keywords = [
            "end of names list",
            "privmsg",
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
        ]
        self.conversation_history = []

    def connect(self):
        if self.log_callback:
            self.log_callback(f"--> Attempting connection to {self.server}:{self.port}...")
        try:
            self.connection = self.client.server().connect(
                self.server, int(self.port), self.nickname
            )
            self.connection.add_global_handler("all_events", self.handle_server_message)
            self.start_keep_alive()
            threading.Thread(target=self.client.process_forever, daemon=True).start()
            if self.log_callback:
                self.log_callback(f"--> Server {self.server} is up!\n")
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"\n!!! Error while connecting: {e} !!!\n")

    def join_channel(self):
        if self.connection:
            try:
                self.connection.join(self.channel)
                if self.log_callback:
                    self.log_callback(f"\n--> Joined channel {self.channel}\n")
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"\n!!! Error joining channel: {e} !!!\n")

    def start_keep_alive(self):
        if self.connection:
            self.connection.ping(self.server)
            self.client.scheduler.execute_after(
                self.keep_alive_interval, self.start_keep_alive
            )

    def disconnect(self):
        if self.log_callback:
            self.log_callback("\n--> Disconnecting...\n")
        if self.connection:
            try:
                self.connection.disconnect("Goodbye!")
                if self.log_callback:
                    self.log_callback("--> Disconnected.\n")
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"!!! Error disconnecting: {e} !!!")
                    
    def handle_server_message(self, connection, event):
        if event.type == "privmsg":
            self.on_private_message(connection, event)
        elif event.type == "mode":
            self.handle_mode_event(connection, event)
        else:
            self.log_raw_messages(connection, event)

    def handle_mode_event(self, connection, event):
        if len(event.arguments) >= 2:
            mode_change = event.arguments[0]  # La modifica del mode (esempio: "+o")
            target = event.arguments[1]  # Il nickname dell'utente coinvolto
            source = irc.client.NickMask(event.source).nick  # Nickname di chi ha eseguito il comando

            if mode_change == "+o" and target == self.nickname:  # Controlla se il bot è stato oppato
                self.log_callback(f"--> {source} has opped {self.nickname}")
                self.send_message(self.channel, f"Thanks for op, {source}! :*")

    def on_private_message(self, connection, event):
        source = event.source.nick
        message = event.arguments[0]

        # Log in grassetto
        if self.log_callback:
            self.log_callback(f"\n({source}) - {message}", bold=True)

        # Gestisci l'autenticazione o genera una risposta
        if source not in self.authenticated_users:
            self.request_authentication(source)
        elif self.authenticated_users[source]:
            self.log_callback(f"--> Generating AI response for {source}...")
            response, role = ask_gpt4(
                query=message,
                conversation_history=self.conversation_history,
                bot_nickname=self.nickname,
                server=self.server,
                channel=self.channel,
                speaker_nickname=source,
            )
            self.send_message(source, response)
        else:
            self.check_password(source, message)


    def log_raw_messages(self, connection, event):
        raw_message = " ".join(event.arguments).strip() if event.arguments else ""
        normalized_message = raw_message.lstrip("-:").strip()
        message_signature = hashlib.sha256(normalized_message.encode()).hexdigest()

        if message_signature in self.logged_messages:
            return

        if any(
            keyword.lower() in normalized_message.lower()
            for keyword in self.exclude_keywords
        ):
            return

        self.logged_messages.add(message_signature)
        if self.log_callback:
            self.log_callback(f"[SERVER]: {normalized_message}")

    def request_authentication(self, nickname):
        if self.log_callback:
            self.log_callback(f"User {nickname} must be authenticated...")
        self.send_message(nickname, "Do you love cats?")
        self.authenticated_users[nickname] = False

    def check_password(self, nickname, password):
        current_time = time.time()
        if nickname in self.failed_attempts:
            if self.failed_attempts[nickname] >= 3:
                if current_time - self.last_attempt_time[nickname] < 120:
                    if self.log_callback:
                        self.log_callback(f"User {nickname} temporarily blocked")
                    return
                else:
                    self.failed_attempts[nickname] = 0

        if hash_password(password) == self.password_hash:
            self.authenticated_users[nickname] = True
            if self.log_callback:
                self.log_callback(f"User {nickname} authenticated")
            self.send_message(nickname, "Ok, say something...")
        else:
            self.failed_attempts[nickname] = self.failed_attempts.get(nickname, 0) + 1
            self.last_attempt_time[nickname] = current_time
            if self.log_callback:
                self.log_callback(f"Failed authentication by {nickname}")
            self.send_message(nickname, "Yuh no cat lover.")

    def send_message(self, target, message):
        if self.connection:
            try:
                sanitized_message = message.replace("\n", " ").replace("\r", " ")
                self.connection.privmsg(target, sanitized_message)
                if self.log_callback:
                    self.log_callback(f"(Chat with {target}) - {sanitized_message}", bold=True)
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"!!! Error sending message to {target}: {e} !!!")

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

    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
        bot_nickname=bot_nickname,
        server=server,
        channel=channel,
        speaker_nickname=speaker_nickname,
        current_datetime=current_datetime,
        news_section=news_section,
    )

    # Check if system prompt exists in the conversation history
    system_idx = next(
        (i for i, m in enumerate(conversation_history) if m["role"] == "system"), None
    )
    if system_idx is not None:
        conversation_history[system_idx]["content"] = system_prompt
    else:
        conversation_history.insert(0, {"role": "system", "content": system_prompt})

    # Append the user's query
    conversation_history.append({"role": "user", "content": query})

    # Limit the history to the last 20 messages, ensuring the system prompt is preserved
    if len(conversation_history) > 20:
        conversation_history = [conversation_history[0]] + conversation_history[-19:]

    # Prepare the payload
    data = {"messages": conversation_history}
    url = "http://localhost:1234/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
    }

    # Send the request to the LLM
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





class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AIRCBot")
        self.geometry("1200x850")
        self.server_var = tk.StringVar(value=f"{srv}")
        self.port_var = tk.StringVar(value=f"{prt}")
        self.nick_var = tk.StringVar(value=f"{nck}")
        self.channel_var = tk.StringVar(value=f"{chn}")
        self.password_var = tk.StringVar()
        self.command_var = tk.StringVar()
        self.msg_var = tk.StringVar()
        self.bot = None
        self.create_widgets()
        self.create_menu()

    def create_widgets(self):
        param_frame = ttk.LabelFrame(self, text="Connection")
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
        ttk.Entry(msg_frame, textvariable=self.msg_var).pack(
            side="left", fill="x", expand=True, padx=5, pady=5
        )
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
        self.log_text.tag_configure("bold", font=("", 12, "bold"))  # Tag per il grassetto

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
        )
        self.bot.connect()

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
                messagebox.showerror("Input Error", "Password cannot be empty.")

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

    def join_channel(self):
        if self.bot:
            self.bot.join_channel()

    def send_message(self):
        if self.bot:
            msg = self.msg_var.get()
            self.bot.send_message(self.bot.channel, msg)
            self.msg_var.set("")

    def send_irc_command(self):
        if not self.bot or not self.bot.connection:
            self.log_message("!!! Not connected to any server. Please connect first !!!")
            return

        cmd = self.command_var.get().strip()
        if cmd.startswith("/"):
            # Remove the initial '/' to process the command
            cmd_parts = cmd[1:].split(" ", 1)
            command = cmd_parts[0].lower()  # Normalize command to lowercase
            params = cmd_parts[1] if len(cmd_parts) > 1 else ""

            # Handle specific commands with additional logic
            if command in ["join", "j"]:
                # Disable /join and /j for security reasons
                self.log_message("!!! The /join command is disabled for security reasons !!!")
                self.command_var.set("")  # Clear the command input field
                return

            elif command == "msg":
                # Format: /msg user message
                parts = params.split(" ", 1)
                if len(parts) == 2:
                    target, message = parts
                    self.bot.connection.send_raw(f"PRIVMSG {target} :{message}")
                    self.log_message(f"--> Command sent: PRIVMSG {target} :{message}")
                else:
                    self.log_message("!!! Invalid format for /msg. Use: /msg user message !!!")

            elif command in ["kick", "k"]:
                # Format: /kick user [reason]
                parts = params.split(" ", 1)
                if len(parts) >= 1:
                    user = parts[0]
                    reason = parts[1] if len(parts) > 1 else ""
                    self.bot.connection.send_raw(f"KICK {self.bot.channel} {user} :{reason}")
                    self.log_message(f"--> Command sent: KICK {self.bot.channel} {user} :{reason}")
                else:
                    self.log_message("!!! Invalid format for /kick. Use: /kick user [reason] !!!")

            elif command == "topic":
                # Format: /topic [new_topic]
                topic = params if params else ""
                self.bot.connection.send_raw(f"TOPIC {self.bot.channel} :{topic}")
                self.log_message(f"--> Command sent: TOPIC {self.bot.channel} :{topic}")

            elif command in ["quit", "q"]:
                # QUIT: /quit [message]
                message = params if params else "Goodbye!"
                self.bot.connection.send_raw(f"QUIT :{message}")
                self.log_message(f"--> Command sent: QUIT :{message}")

            elif command in ["whois", "w"]:
                # Format: /whois user
                if params:
                    self.bot.connection.send_raw(f"WHOIS {params}")
                    self.log_message(f"--> Command sent: WHOIS {params}")
                else:
                    self.log_message("!!! Invalid format for /whois. Use: /whois user !!!")

            elif command in ["op", "o"]:
                # Format: /op user
                if params:
                    self.bot.connection.send_raw(f"MODE {self.bot.channel} +o {params}")
                    self.log_message(f"--> Command sent: MODE {self.bot.channel} +o {params}")
                else:
                    self.log_message("!!! Invalid format for /op. Use: /op user !!!")

            else:
                # Generic commands sent as-is
                try:
                    self.bot.connection.send_raw(f"{command.upper()} {params}")
                    self.log_message(f"--> Command sent: {command.upper()} {params}")
                except Exception as e:
                    self.log_message(f"!!! Error sending command: {e} !!!")
        else:
            self.log_message("!!! Commands must start with '/' !!!")

        self.command_var.set("")  # Clear the command input field

    def send_message(self):
        if not self.bot or not self.bot.connection:
            self.log_message("!!! Not connected to any server. Please connect first !!!")
            return

        msg = self.msg_var.get().strip()
        if msg:
            try:
                self.bot.connection.privmsg(self.bot.channel, msg)
                self.log_message(f"--> Message sent to channel {self.bot.channel}: {msg}")
            except Exception as e:
                self.log_message(f"!!! Error sending message: {e} !!!")
        self.msg_var.set("")  # Clear the message input field

    def on_enter_command(self, event):
        self.send_irc_command()


    def on_enter_command(self, event):
        self.send_irc_command()
            
    def log_message(self, text, bold=False):
        def _append():
            if bold:
                self.log_text.insert(tk.END, text + "\n", "bold")  # Usa il tag "bold"
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
        help_text = (
            "AIRCBot Help:\n\n"
            "1. Connection Parameters:\n"
            "   - Server: The IRC server to connect to.\n"
            "   - Port: The port number for the IRC server (default is usually 6667).\n"
            "   - Nick: Your desired nickname.\n"
            "   - Channel: The channel to join (e.g., #example).\n"
            "   - Password: Your bot password for authentication.\n\n"
            "2. Actions:\n"
            "   - Connect: Establish a connection to the IRC server.\n"
            "   - Join Channel: Join the specified channel.\n"
            "   - Disconnect: Disconnect from the server.\n\n"
            "3. Messaging:\n"
            "   - Use the text field to send a message to the channel.\n"
            "   - Press 'Send' to deliver your message.\n\n"
            "4. IRC Commands:\n"
            "   - Enter an IRC command (e.g., /nick newnick) and press 'Send'.\n"
            "   - Note: /join commands are disabled for security reasons.\n\n"
            "5. Console:\n"
            "   - The console displays messages and server events.\n\n"
            "6. Troubleshooting:\n"
            "   - Ensure the server and port are correct.\n"
            "   - Check your internet connection if you encounter issues.\n"
            "   - Use a strong password for bot authentication.\n"
        )

        help_window = tk.Toplevel(self)
        help_window.title("Help")
        help_window.geometry("600x400")

        help_text_widget = scrolledtext.ScrolledText(
            help_window, wrap="word", font=("Arial", 12), state="normal"
        )
        help_text_widget.insert("1.0", help_text)
        help_text_widget.configure(state="disabled")
        help_text_widget.pack(fill="both", expand=True, padx=10, pady=10)


if __name__ == "__main__":
    app = App()
    app.mainloop()
