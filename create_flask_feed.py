"""
This code is only an example, it is not intended to be used in production

virtual environments like venv or poetry are best practice to install packages

pip install flask
pip install flask_cors
pip install pyopenssl

This code is only an example, it is not intended to be used in production
"""
import flask
from flask import send_from_directory

# set root path to the folder where the flask app is started
app = flask.Flask(__name__, static_url_path='')
app.config["DEBUG"] = True


# flask was started in /users/[user name]/ioc_feed
# json_to_csv.py writes csv files to output directory /users/[user name]/ioc_feed/output
@app.route('/output/<path:path>', methods=["get"])
def download(path):
    try:
        return send_from_directory('output', path)
        # return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
        # return send_from_directory(directory='output', filename=filename, as_attachment=True, cache_timeout=0)
    except FileNotFoundError:
        abort(404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

# app.config['JSON_SORT_KEYS'] = False
# CORS(app, expose_headers=["Content-Disposition"])
# use send_file to download file from / root directory
# from flask import send_file
# use send_from_directory to download file from subdirectory
# from flask_cors import CORS
# @app.route("/", methods=["GET"])
# def home():
#     return     <>
#     <h3> Serving CSV file </h3>

# @app.route("/get-json", methods=["get"])
# def get_json():
#     return jsonify(parsed_json_response)


# app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True

# if requesting a specific file from the flask root directory
# @app.route("/get-csv/<csv_id>", methods=["get"])
# def get_csv(csv_id):
#     try:
#         return send_file(csv_id)
#     except FileNotFoundError:
#         abort(404)

# use the line below if you need ssl replication
# app.run(host="0.0.0.0", port=5000, ssl_context='adhoc')
