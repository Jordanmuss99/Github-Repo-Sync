# GitHub Repository Synchronization Tool

This Python program allows you to synchronize a local directory with a GitHub repository. It provides a graphical user interface (GUI) for easy configuration and management of the synchronization process. This program is meant to be used as a way to keep a repo automatically updated on a machine or server without manually hitting pull. 

## Features

- Clone a GitHub repository to a local directory
- Synchronize changes from the remote repository to the local directory
- Monitor the repository for changes and automatically synchronize
- Display synchronization history and status
- View repository information, commit history, and file changes
- Support for private repositories with access tokens

## Requirements

- Python 3.x
- Flask
- GitPython
- tkinter (included in Python standard library)
- configparser (included in Python standard library)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/Jordanmuss99/Github-Repo-Sync.git
   ```
3. Navigate to the project directory:
   ```
   cd Github-Repo-Sync
   ```
5. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

   ## Usage

1. Run the program:
   ```
   python autosync.py
   ```
2. The GUI window will appear. Fill in the repository information:
- URL: Enter the URL of the GitHub repository.
- Local Path: Enter the local directory path where the repository will be cloned.
- Branch: Enter the branch name to synchronize with (default is "main").
- Log File: Enter the path to the log file for storing synchronization history.
- Private Repository: Check this box if the repository is private and requires an access token.
- Access Token: If the repository is private, enter your personal access token.

3. Click the "Start Monitoring" button to begin monitoring the repository for changes. The program will automatically synchronize any changes detected.

4. You can also perform a one-time synchronization by clicking the "Perform One-Time Synchronization" button.

5. Use the other buttons to display synchronization history, last synchronization status, repository information, commit history, branch list, and file changes for a specific commit.

## Configuration

The program uses a configuration file (`config.ini`) to store the repository information and settings. The configuration file is automatically created and updated when you modify the settings in the GUI.
Please note that your Access Token is readable and is not encrypted in the config.ini

## Webhook Integration

The program includes a Flask web server that listens for webhook events from GitHub. When a push event is received for the "main" branch, the program automatically synchronizes the repository.

To set up the webhook integration:

1. Make sure your system is accessible from the internet and has a public IP address or domain name.

2. Configure your GitHub repository's webhook settings to send push events to the URL: `http://your-public-ip:8000/webhook`.

3. The program will automatically handle the webhook events and synchronize the repository when changes are pushed to the "main" branch.

## License

This program is licensed under the [MIT License](LICENSE).
   
