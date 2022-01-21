import json

file_name = 'confusion_matrix_1641788946.5192919'
with open(f"{file_name}.log") as file:
	data = file.readlines()


result = []
for line in data:
	comps = line.replace("'", "").split(' ')

	current = {}
	for com in comps:
		parts = com.split('=')
		key = parts[0]
		value = parts[1].strip()

		current[key] = value

		if current[key].isdecimal():
			current[key] = int(current[key])
		elif '.' in current[key]:
			current[key] = float(current[key])
		elif '[' in current[key]:
			params = json.loads(current[key])
			del current[key]
			current['db size'] = params[0]
			if len(params) > 1:
				current['min voters'] = params[1]

	result.append(current)

with open(f"{file_name}.json", 'w') as file:
	json.dump(result, file)
