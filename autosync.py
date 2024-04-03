import os
import datetime
import time
import configparser
import git
from git import Repo, InvalidGitRepositoryError, GitCommandError
from flask import Flask, request
from threading import Thread
import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog, filedialog
import requests
global gui

app = Flask(__name__)

class SyncGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("GitHub Repository Synchronization Tool")

        config = configparser.ConfigParser()
        config.read('config.ini')

        self.repo_url = config.get('repository', 'url', fallback='')
        self.local_path = config.get('repository', 'local_path', fallback='')
        self.branch = config.get('repository', 'branch', fallback='')
        self.log_file = config.get('settings', 'log_file', fallback='')
        self.is_private_repo = config.getboolean('repository', 'is_private', fallback=False)
        self.access_token = config.get('settings', 'access_token', fallback='')
        self.flask_thread = None

        self.create_widgets()
        self.load_config()

    def load_config(self):
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, self.repo_url)

        self.local_path_entry.delete(0, tk.END)
        self.local_path_entry.insert(0, self.local_path)

        self.branch_entry.delete(0, tk.END)
        self.branch_entry.insert(0, self.branch)

        self.log_file_entry.delete(0, tk.END)
        self.log_file_entry.insert(0, self.log_file)

        self.is_private_var.set(self.is_private_repo)

        self.access_token_entry.delete(0, tk.END)
        self.access_token_entry.insert(0, self.access_token)

    def save_config(self):
        self.update_config()
        self.display_output("Configuration saved.")

    def run(self):
        self.window.mainloop()

    def toggle_monitoring(self):
        if self.monitoring_var.get():
            self.monitoring_button.config(text="Start Monitoring")
            self.stop_webhook()
        else:
            self.monitoring_button.config(text="Stop Monitoring")
            self.start_webhook()
        
        self.monitoring_var.set(not self.monitoring_var.get())

    def start_webhook(self):
        if self.flask_thread is None or not self.flask_thread.is_alive():
            self.flask_thread = Thread(target=run_flask_app)
            self.flask_thread.daemon = True
            self.flask_thread.start()
            self.display_output("Webhook started.")

    def stop_webhook(self):
        if self.flask_thread is not None and self.flask_thread.is_alive():
            # Send a request to shutdown the Flask app gracefully
            requests.get("http://localhost:8000/shutdown")
            self.flask_thread.join(timeout=5)
            self.display_output("Webhook stopped.")

    def create_widgets(self):
        main_frame = ttk.Frame(self.window)
        main_frame.pack(padx=10, pady=10)

        # Repository Information
        info_frame = ttk.LabelFrame(main_frame, text="Repository Information")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(info_frame, text="URL:").grid(row=0, column=0, sticky=tk.W)
        self.url_entry = ttk.Entry(info_frame, width=50)
        self.url_entry.grid(row=0, column=1, sticky=tk.W)

        ttk.Label(info_frame, text="Local Path:").grid(row=1, column=0, sticky=tk.W)
        self.local_path_entry = ttk.Entry(info_frame, width=50)
        self.local_path_entry.grid(row=1, column=1, sticky=tk.W)
        ttk.Button(info_frame, text="Browse", command=self.browse_local_path).grid(row=1, column=2, padx=5)

        ttk.Label(info_frame, text="Branch:").grid(row=2, column=0, sticky=tk.W)
        self.branch_entry = ttk.Entry(info_frame, width=50)
        self.branch_entry.grid(row=2, column=1, sticky=tk.W)

        ttk.Label(info_frame, text="Log File:").grid(row=3, column=0, sticky=tk.W)
        self.log_file_entry = ttk.Entry(info_frame, width=50)
        self.log_file_entry.grid(row=3, column=1, sticky=tk.W)

        self.is_private_var = tk.BooleanVar()
        ttk.Checkbutton(info_frame, text="Private Repository", variable=self.is_private_var).grid(row=4, column=0, sticky=tk.W)

        ttk.Label(info_frame, text="Access Token:").grid(row=5, column=0, sticky=tk.W)
        self.access_token_entry = ttk.Entry(info_frame, width=50, show="*")
        self.access_token_entry.grid(row=5, column=1, sticky=tk.W)

        # Add the "Save Config" button
        save_config_button = ttk.Button(info_frame, text="Save Config", command=self.save_config)
        save_config_button.grid(row=6, column=1, padx=5, pady=5)

        # Actions
        actions_frame = ttk.LabelFrame(main_frame, text="Actions")
        actions_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.monitoring_var = tk.BooleanVar()
        self.monitoring_button = ttk.Button(actions_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.monitoring_button.grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(actions_frame, text="Perform One-Time Synchronization", command=self.sync_repo).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(actions_frame, text="Display Sync History", command=self.display_sync_history).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(actions_frame, text="Display Last Synchronization Status", command=self.display_last_sync_status).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(actions_frame, text="Display Repository Information", command=self.display_repo_info).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(actions_frame, text="Display Commit History", command=self.display_commit_history).grid(row=3, column=0, padx=5, pady=5)
        ttk.Button(actions_frame, text="Display Branch List", command=self.display_branch_list).grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(actions_frame, text="Display File Changes for a Commit", command=self.display_file_changes).grid(row=4, column=0, padx=5, pady=5)

        # Output
        output_frame = ttk.LabelFrame(main_frame, text="Output")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.output_text = scrolledtext.ScrolledText(output_frame, width=80, height=20)
        self.output_text.pack(fill=tk.BOTH, expand=True)

    def browse_local_path(self):
        local_path = filedialog.askdirectory(title="Select the local path")
        self.local_path_entry.delete(0, tk.END)
        self.local_path_entry.insert(0, local_path)

    def start_monitoring(self):
        self.update_config()
        monitor_thread = Thread(target=monitor_repo, args=(self, 60))
        monitor_thread.daemon = True
        monitor_thread.start()

    def sync_repo(self):
        self.update_config()
        sync_repo_thread = Thread(target=sync_repo, args=(self,))
        sync_repo_thread.start()

    def display_sync_history(self):
        self.update_config()
        display_sync_history(self)

    def display_last_sync_status(self):
        self.update_config()
        display_last_sync_status(self)

    def display_repo_info(self):
        self.update_config()
        display_repo_info(self)

    def display_commit_history(self):
        self.update_config()
        num_commits = simpledialog.askinteger("Commit History", "Enter the number of commits to display:")
        if num_commits:
            display_commit_history(self, num_commits)

    def display_branch_list(self):
        self.update_config()
        display_branch_list(self)

    def display_file_changes(self):
        self.update_config()
        commit_hash = simpledialog.askstring("File Changes", "Enter the commit hash:")
        if commit_hash:
            display_file_changes(self, commit_hash)

    def display_output(self, message):
        def _display():
            self.output_text.insert(tk.END, message + "\n")
            self.output_text.see(tk.END)

        self.window.after(0, _display)

    def update_config(self):
        config = configparser.ConfigParser()

        config.read('config.ini')

        if not config.has_section('repository'):
            config.add_section('repository')
        config.set('repository', 'url', self.url_entry.get())
        config.set('repository', 'local_path', self.local_path_entry.get())
        config.set('repository', 'branch', self.branch_entry.get())
        config.set('repository', 'is_private', str(self.is_private_var.get()))

        if not config.has_section('settings'):
            config.add_section('settings')
        config.set('settings', 'log_file', self.log_file_entry.get())
        config.set('settings', 'access_token', self.access_token_entry.get())

        with open('config.ini', 'w') as configfile:
            config.write(configfile)

        def run(self):
            self.window.mainloop()

def get_latest_commit_hash(repo, branch):
    try:
        latest_commit_hash = repo.rev_parse(f"origin/{branch}").hexsha
        return latest_commit_hash
    except (git.BadName, ValueError):
        return None

def sync_repo(gui):
    repo_url = gui.repo_url
    local_path = gui.local_path
    branch = gui.branch
    log_file = gui.log_file
    is_private_repo = gui.is_private_repo
    access_token = gui.access_token

    try:
        if not os.path.exists(local_path):
            gui.display_output(f"Cloning repository to {local_path} \nThis can sometimes take a little while...")
            if is_private_repo and access_token:
                repo_url_with_token = repo_url.replace("https://", f"https://{access_token}@")
                repo = Repo.clone_from(repo_url_with_token, local_path, branch=branch)
            else:
                repo = Repo.clone_from(repo_url, local_path, branch=branch)
            gui.display_output(f"Repository cloned successfully. Branch: {branch}")
        else:
            gui.display_output(f"Checking for changes in repository...")
            repo = Repo(local_path)
            if repo.active_branch.name != branch:
                gui.display_output(f"Switching to branch: {branch}")
                repo.git.checkout(branch)

            current_commit_hash = repo.head.commit.hexsha
            origin = repo.remote('origin')
            origin.fetch()
            latest_commit_hash = get_latest_commit_hash(repo, branch)

            if latest_commit_hash is None:
                gui.display_output(f"Failed to fetch the latest commit hash for branch: {branch}. Skipping synchronization.")
            elif current_commit_hash != latest_commit_hash:
                gui.display_output(f"Pulling changes from repository to {local_path}...")
                if is_private_repo and access_token:
                    repo_url_with_token = repo_url.replace("https://", f"https://{access_token}@")
                    origin.set_url(repo_url_with_token)
                origin.pull(branch, force=True)
                gui.display_output(f"Changes synchronized. Branch: {branch}")

                commit_range = f"{current_commit_hash}..{latest_commit_hash}"
                commits = list(repo.iter_commits(commit_range))
                changed_files = [(file, commit.message.strip(), commit.author.name) for commit in commits for file in commit.stats.files]

                if changed_files:
                    log_message = f"Synchronization completed at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.\nChanged files:\n"
                    log_message += "\n".join(f"- {file}\n  Commit message: {message}\n  Committer: {committer}" for file, message, committer in changed_files)
                    log_message += "\n"

                    gui.display_output(log_message)

                    with open(log_file, "a") as file:
                        file.write(log_message)
            else:
                gui.display_output(f"No changes detected. Branch: {branch}")
    except (InvalidGitRepositoryError, GitCommandError) as e:
        gui.display_output(f"Error occurred: {str(e)}")
    except Exception as e:
        gui.display_output(f"An unexpected error occurred: {str(e)}")

def display_last_sync_status(gui):
    log_file = gui.log_file

    if os.path.exists(log_file):
        with open(log_file, "r") as file:
            lines = file.readlines()
            if lines:
                last_sync = lines[-1].strip()
                gui.display_output(f"Last Synchronization Status:\n{last_sync}")
            else:
                gui.display_output("No synchronization history found.")
    else:
        gui.display_output("No synchronization history found.")

def display_repo_info(gui):
    repo_url = gui.repo_url
    local_path = gui.local_path
    branch = gui.branch

    repo_info = f"Repository Information:\nURL: {repo_url}\nLocal Path: {local_path}\nBranch: {branch}\n"

    if os.path.exists(local_path):
        repo = Repo(local_path)
        repo_info += f"Current Commit: {repo.head.commit.hexsha}\nLast Commit Date: {repo.head.commit.committed_datetime}\n"
    else:
        repo_info += "Local repository not found.\n"

    gui.display_output(repo_info)

def monitor_repo(gui, interval):
    while True:
        try:
            sync_repo(gui)
            time.sleep(interval)
        except KeyboardInterrupt:
            gui.display_output("Monitoring stopped.")
            break

def display_sync_history(gui):
    log_file = gui.log_file

    if os.path.exists(log_file):
        with open(log_file, "r") as file:
            sync_history = file.read()
            gui.display_output(f"Synchronization History:\n{sync_history}")
    else:
        gui.display_output("No synchronization history found.")

def display_commit_history(gui, num_commits):
    local_path = gui.local_path
    branch = gui.branch

    if os.path.exists(local_path):
        repo = Repo(local_path)
        commits = list(repo.iter_commits(branch, max_count=num_commits))
        commit_history = f"Last {num_commits} commits in branch '{branch}':\n"
        for commit in commits:
            commit_history += f"Commit: {commit.hexsha}\nAuthor: {commit.author}\nDate: {commit.committed_datetime}\nMessage: {commit.message}\n---\n"
        gui.display_output(commit_history)
    else:
        gui.display_output("Local repository not found.")

def display_branch_list(gui):
    local_path = gui.local_path

    if os.path.exists(local_path):
        repo = Repo(local_path)
        branches = [branch.name for branch in repo.branches]
        branch_list = "Branches:\n" + "\n".join(branches)
        gui.display_output(branch_list)
    else:
        gui.display_output("Local repository not found.")

def display_file_changes(gui, commit_hash):
    local_path = gui.local_path
    branch = gui.branch

    if os.path.exists(local_path):
        repo = Repo(local_path)
        try:
            commit = repo.commit(commit_hash)
            file_changes = f"Changes in commit: {commit_hash}\nAuthor: {commit.author}\nDate: {commit.committed_datetime}\nMessage: {commit.message}\nModified files:\n"
            file_changes += "\n".join(f"- {item}" for item in commit.stats.files)
            file_changes += "\n---\n"
            gui.display_output(file_changes)
        except (git.BadName, ValueError):
            gui.display_output(f"Invalid commit hash: {commit_hash}")
    else:
        gui.display_output("Local repository not found.")

@app.route("/webhook", methods=["POST"])
def handle_webhook():
    global gui
    data = request.json
    if data["ref"] == "refs/heads/main":
        repo_url = data["repository"]["clone_url"]
        branch = "main"
        log_file = "sync_log.txt"
        sync_repo(gui)  # Pass the gui instance to sync_repo
    return "OK"

def run_flask_app():
    @app.route("/shutdown", methods=["GET"])
    def shutdown():
        terminate_func = request.environ.get("werkzeug.server.shutdown")
        if terminate_func:
            terminate_func()
        return "Flask app shutting down..."

    app.run(host='0.0.0.0', port=8000)

def main():
    global gui
    
    # Create the GUI
    gui = SyncGUI()
    
    # Start the webhook
    gui.start_webhook()
    
    # Run the GUI
    gui.run()

if __name__ == "__main__":
    main()