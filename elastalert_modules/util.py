

def convert_array_to_object(array):
    json = {}
    for idx in range(len(array)):
        json[str(idx)] = array[idx]
    return json

def parse_object(match):
    parsed = {}
    for key in match.keys():
        if not isinstance(match[key], list):
            continue
        if len(match[key]) == 0:
            continue

        # Converts array terms into objects
        parsed[key + '_parsed'] = convert_array_to_object(match[key])

        for sk, value in match[key][0].iteritems():
            value_array = []
            if (sk == 'type' or sk == 'errors' or sk == 'input') and isinstance(value, list):
                value_array = [sv for v in match[key] for sv in v[sk]]
            else:
                value_array = [v[sk] for v in match[key]]
            parsed[key + '_parsed'][sk] = ", ".join(str(va) for va in set(value_array))
    return parsed
    