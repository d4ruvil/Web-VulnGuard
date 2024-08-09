from flask import Flask, render_template, request
from csrf_detector import main as detect_csrf
from sqli_detector import detect_sqli
from ssrf_detector import check_ssrf
from xxe_detector import detect_xxe

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = {
        'csrf': '',
        'sqli': '',
        'ssrf': '',
        'xxe': ''
    }
    if request.method == 'POST':
        vulnerability = request.form.get('vulnerability')
        url = request.form.get('url')
        param = request.form.get('param')
        cookies = request.form.get('cookies')

        if vulnerability == 'csrf' or vulnerability == 'all':
            result['csrf'] = detect_csrf(url)
        if vulnerability == 'ssrf' or vulnerability == 'all':
            result['ssrf'] = check_ssrf(url)
        if vulnerability == 'xxe' or vulnerability == 'all':
            result['xxe'] = detect_xxe(url, cookies)
        if vulnerability == 'sqli' or vulnerability == 'all':
            result['sqli'] = detect_sqli(url, param)

        return render_template('result.html', result=result)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
