import tkinter as tk
from tkinter import messagebox
import requests
import base64

def send_request():
    url = url_entry.get()
    method = method_dropdown.get()
    username = username_entry.get()
    password = password_entry.get()
    body = post_data_entry.get() if method == "POST" else None

    headers = {}
    if username and password:
        auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {auth_string}"

    try:
        response = requests.request(method, url, headers=headers, data=body)
        response_text = f"Status: {response.status_code}\nData: {response.text}"
        response_text_area.delete(1.0, tk.END)
        response_text_area.insert(tk.INSERT, response_text)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

window = tk.Tk()
window.title("HTTP Request Client")

url_label = tk.Label(window, text="URL:")
url_label.pack(pady=5)
url_entry = tk.Entry(window, width=50)
url_entry.pack(pady=5)

method_label = tk.Label(window, text="Method:")
method_label.pack(pady=5)
method_options = ["GET", "POST", "PUT", "DELETE"]
method_dropdown = tk.StringVar(window)
method_dropdown.set(method_options[0])
method_menu = tk.OptionMenu(window, method_dropdown, *method_options)
method_menu.pack(pady=5)

post_data_label = tk.Label(window, text="POST Data:")
post_data_label.pack(pady=5)
post_data_entry = tk.Entry(window, width=50)
post_data_entry.pack(pady=5)

username_label = tk.Label(window, text="Username:")
username_label.pack(pady=5)
username_entry = tk.Entry(window, width=20)
username_entry.pack(pady=5)

password_label = tk.Label(window, text="Password:")
password_label.pack(pady=5)
password_entry = tk.Entry(window, width=20, show="*")
password_entry.pack(pady=5)

send_button = tk.Button(window, text="Send Request", command=send_request)
send_button.pack(pady=5)

response_text_area = tk.Text(window, width=60, height=10)
response_text_area.pack(pady=5)

window.mainloop()