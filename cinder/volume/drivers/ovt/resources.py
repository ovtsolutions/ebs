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