RESOURCE_CONF = '''
resource {resource_id} {{
    device minor {minor};
    protocol {protocol};
    meta-disk internal;{backends}
}}'''
REPLICATION_PROTOCOLS = {'async': 'A', 'semi-sync': 'B', 'full-sync': 'C'}
BACKEND = \
"""
    floating {address}:{port} {{
        disk    {disk};
    }}"""
HTTP_HEADER_X_EV3_DATE='x-ev3-date'
HTTP_HEADER_X_EV3_TOKEN='x-ev3-token'
