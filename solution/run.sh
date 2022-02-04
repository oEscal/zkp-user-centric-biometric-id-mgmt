#python upscaling.py
# python3 generate_fingerprint_thresholds.py -d min -n upscaled_normal -i fingerprints_database/fingerprints_class
# python3 generate_fingerprint_thresholds.py -d min -n upscaled_edsr -i fingerprints_database/fingerprints_class_upscaled_edsr
# python3 generate_fingerprint_thresholds.py -d min -n upscaled_espcn -i fingerprints_database/fingerprints_class_upscaled_espcn
# python3 generate_fingerprint_thresholds.py -d min -n upscaled_fsrcnn -i fingerprints_database/fingerprints_class_upscaled_fsrcnn
# python3 generate_fingerprint_thresholds.py -d min -n upscaled_lapsrn -i fingerprints_database/fingerprints_class_upscaled_lapsrn

python3 generate_fingerprint_thresholds.py -d voting -n voting_class_new -i fingerprints_database/fingerprints_class
# python3 generate_fingerprint_thresholds.py -d min -n min_class -i fingerprints_database/fingerprints_class
# python3 generate_fingerprint_thresholds.py -d mean -n mean_class -i fingerprints_database/fingerprints_class
# python3 generate_fingerprint_thresholds.py -d max -n max_class -i fingerprints_database/fingerprints_class

