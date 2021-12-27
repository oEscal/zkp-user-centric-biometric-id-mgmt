import os
from generate_fingerprint_thresholds import get_params_from_filename

a = os.listdir('fingerprints')

for i in a:
    params = list(get_params_from_filename(i))
    if params[-2] != 10:
        os.remove(f'fingerprints/{i}')

    else:
        params.pop(4)
        params_str = "_".join(map(str, params)) + '.png'
        os.rename(f'fingerprints/{i}', f'fingerprints/{params_str}')
