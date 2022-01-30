import os
import json
import dash
import pandas as pd
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px


def create_score_evolution_figure(data, title="Score evolution"):
	labels = ['Iteration', 'Score']
	markers = False
	df = pd.DataFrame({
		labels[0]: list(range(len(data))),
		labels[1]: data
	})
	if len(data) == 1:
		markers = True

	fig = px.line(df, x=labels[0], y=labels[1], title=title, markers=markers)
	fig.update_layout(clickmode='event+select')
	fig.update_traces(marker_size=20)
	return fig


def plot_bars(data, labels, title='Timestamp'):
	df = pd.DataFrame({
		labels[0]: list(data.keys()),
		labels[1]: list(data.values())
	})

	fig = px.bar(df, x=labels[0], y=labels[1], title=title, text_auto=True)
	fig.update_layout(clickmode='event+select')
	return fig


def get_data(path):
	with open(path, 'r') as f:
		return json.load(f)


def main(logs_path):
	external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']
	app = dash.Dash(__name__, external_stylesheets=external_stylesheets)
	styles = {
		'pre': {
			'border': 'thin lightgrey solid',
			'overflowX': 'scroll',
		},
		'row': {
			'display': 'flex',
			'justifyContent': 'center'
		}
	}

	processes_path = dict([(path, f'{logs_path}/{path}') for path in os.listdir(logs_path)])
	score_evolution_fig = create_score_evolution_figure([])

	app.layout = html.Div([
		html.Div([
			'Choose the process',
			dcc.Dropdown(
				id='process_list',
				options=[{'label': k, 'value': v} for k, v in processes_path.items()]
			)]),
		html.Div([
			'Choose the plot',
			dcc.Dropdown(
				id='plot_list',
				options=[]
			)
		]),
		dcc.Graph(
			id='plot_score_evolution',
			figure=score_evolution_fig,
			config={
				'editable': True,
				'toImageButtonOptions': {'scale': 3}
			},
		),
	])

	@app.callback(Output('plot_list', 'options'), Output('plot_list', 'value'),
	              Input('process_list', 'value'))
	def update_process_choice(value):
		graphics_path = os.listdir(value) if value is not None else []
		new_value = graphics_path[0] if len(graphics_path) > 0 else None
		return [{'label': path, 'value': f'{value}/{path}'} for path in graphics_path], new_value

	@app.callback(Output('plot_score_evolution', 'figure'),
	              Input('plot_list', 'value'))
	def update_graphics(value):
		label = value.split('/')[1]
		if label == 'fingerprint' or label == 'facial':
			current_data = [p.get('score', 0) for p in get_data(value)] if value is not None else []
			return create_score_evolution_figure(current_data)
		elif label == 'upscaling_time':
			current_data = dict([(k, v.get('total')) for k, v in get_data(value).items()]) if value is not None else []
			return plot_bars(current_data, ['Method', 'Timestamp'], f'Total timestamp foreach upscalling method')
		elif label == 'compare_facial':
			current_data = dict([(k, v.get('score')) for k, v in get_data(value).items()]) if value is not None else []
			return plot_bars(current_data, ['Decision Algorithm', 'Score'], f'Best score of each decision algorithm')

	return app


if __name__ == '__main__':
	logs_path = 'logs'
	app_ = main(logs_path)
	app_.run_server(debug=True, host='0.0.0.0')
