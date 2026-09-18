"""Fixture validation only; public transport acceptance is a separate gate."""
from awiki_open_server.protocol.anp_adapter import did_resolution_url, require_did_document_binding
from tests.fixtures.web_did_peer import prepare


def test_public_web_peer_material_has_distinct_valid_keys_and_explicit_home(tmp_path):
    config=prepare(tmp_path/'peer','/protocol-peer-fixture')
    for kind in ['home','actor']:
        doc=config[kind+'_document']
        require_did_document_binding(doc)
        assert did_resolution_url(doc['id']) == f'https://rwiki.cn/protocol-peer-fixture/{kind}/did.json'
        assert doc['service'][0]['serviceDid']==config['home_did']
        assert (tmp_path/'peer'/f'{kind}-key.pem').stat().st_mode & 0o777 == 0o600
    assert config['home_document']['verificationMethod'][0]['publicKeyMultibase'] != config['actor_document']['verificationMethod'][0]['publicKeyMultibase']
    assert 'PRIVATE KEY' not in (tmp_path/'peer/public-config.json').read_text()


def test_web_home_http_signature_is_real_and_bound_to_body(tmp_path):
    import pytest
    from awiki_open_server.service_identity import ServiceIdentity, verify_peer_http_signature
    from awiki_open_server.shared.errors import Unauthorized
    config=prepare(tmp_path/'signer','/protocol-peer-signature')
    did=config['home_did'];document=config['home_document']
    signer=ServiceIdentity(did,document,(tmp_path/'signer/home-key.pem').read_text(),did+'#key-1')
    url='https://rwiki.cn/anp-im/rpc';body=b'{"verification":"web-home"}'
    headers={'Content-Type':'application/json','x-anp-source-service-did':did}
    headers.update(signer.sign_headers(url,'POST',headers,body))
    assert verify_peer_http_signature(service_did_document=document,method='POST',url=url,headers=headers,body=body)==did+'#key-1'
    with pytest.raises(Unauthorized):
        verify_peer_http_signature(service_did_document=document,method='POST',url=url,headers=headers,body=body+b' ')
