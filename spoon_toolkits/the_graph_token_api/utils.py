import string

def normalize_ethereum_contract_address(contract_address: str) -> str:
    if not contract_address.startswith('0x'):
        contract_address = '0x' + contract_address
    if len(contract_address) != 42:
        raise ValueError(f'Invalid contract address {contract_address}. Length is not 42.')
    for c in contract_address[2:]:
        if not c in string.hexdigits:
            raise ValueError(f'Invalid contract address {contract_address}. Non hexadecimal char {c}.')
    return contract_address