import os
import shutil

# Create required directories
folders = [
    'templates',
    'static/css',
    'static/js',
    'static/images'
]

for folder in folders:
    os.makedirs(folder, exist_ok=True)

# Move HTML files to templates/
html_files = ['index.html', 'login.html', 'register.html']
for file in html_files:
    if os.path.exists(file):
        shutil.move(file, f'templates/{file}')

# Move CSS and JS files to static/
if os.path.exists('css/style.css'):
    shutil.move('css/style.css', 'static/css/style.css')
    shutil.rmtree('css', ignore_errors=True)

if os.path.exists('js/register.js'):
    shutil.move('js/register.js', 'static/js/register.js')
if os.path.exists('js/main.js'):
    shutil.move('js/main.js', 'static/js/main.js')
if os.path.exists('js/login.js'):
    shutil.move('js/login.js', 'static/js/login.js')
shutil.rmtree('js', ignore_errors=True)

print("✅ Project structure organized successfully.")
