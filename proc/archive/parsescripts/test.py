import stix2
observedDataFile = stix2.ObservedData(
    id="observed-data--cf8eaa41-6f4c-482e-89b9-9cd2d6a83cb1",
    created="2017-02-28T19:37:11.213Z",
    modified="2017-02-28T19:37:11.213Z",
    first_observed="2017-02-27T21:37:11.213Z",
    last_observed="2017-02-27T21:37:11.213Z",
    number_observed=1,
    created_by_ref="identity--7865b6d2-a4af-45c5-b582-afe5ec376c33",
    objects={
        "0": {
            "type": "file",
            "hashes": {
                "MD5": "1717b7fff97d37a1e1a0029d83492de1",
                "SHA-1": "c79a326f8411e9488bdc3779753e1e3489aaedea"
            },
            "name": "resume.pdf",
            "size": 83968
        }
    },
    allow_custom = True
)
