from flask import Flask, request, session, g, redirect, url_for, abort, \
render_template, flash

import flask_shelve as shelve
from acltk import ACLConfig, cafBlock
from acltk.pfsenseSemantics import pfsenseParserOptions

app = Flask(__name__, template_folder='tpl')
app.jinja_env.add_extension('jinja2.ext.loopcontrols')

app.config['SHELVE_FILENAME'] = '/tmp/test.db'

shelve.init_app(app)

@app.route('/add', methods=['POST'])
def add():
	if request.method == 'POST':
		file = request.files['file']
		try:
			cfg = ACLConfig.fromFile(file.stream, options=pfsenseParserOptions(fetch_urltable=False))
			db = shelve.get_shelve()
			db[cfg.name] = cfg
			return redirect(url_for('show', config=cfg.name))
		except TypeError:
			return redirect(url_for('index'))



@app.route('/', methods=['GET','POST'])
def index():
	db = shelve.get_shelve()
	if request.method == 'GET':
		return render_template('index.html', db=db)
	elif request.method == 'POST':
		pass


@app.route('/show', methods=['GET','POST'])
def show():
	db = shelve.get_shelve()
	if request.method == 'GET':
		config=request.args.get('config')
		if config not in db:
			abort(404)
		acls = db[config]
		exp = request.args.get('exp', False)

		if exp:
			acls.expand()

		selection = None
		sns = request.args.get('sns', False)
		cafString=request.args.get('caf')
		warning = None
		if cafString and len(cafString) > 0:
			try:
				caf = cafBlock.fromString(cafString)
				selection = caf.run(acls.rules)
				selection = acls.resolve(selection)
			except Exception as e:
				warning = str(e)
		else:
			cafString = ""
		return render_template('show.html', aclconfig=acls, args = {'show_not_selected':sns, 'expand_groups':exp, 'warning':warning}, selection=selection, caf=cafString)

if __name__ == "__main__":
	app.run(debug=True)
