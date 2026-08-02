from __future__ import annotations
import re
from typing import Callable, List, Optional
from .models import Packet
from .utils import in_network
Predicate = Callable[[Packet], bool]
TOKEN_RE = re.compile('\\(|\\)|"[^"]*"|\\\'[^\\\']*\\\'|[<>=!]=?|[^\\s()]+')
PROTOCOL_KEYWORDS = {'tcp': lambda p: p.tcp is not None, 'udp': lambda p: p.udp is not None, 'icmp': lambda p: p.icmp is not None, 'ip': lambda p: p.ip is not None and p.ip.version == 4, 'ip4': lambda p: p.ip is not None and p.ip.version == 4, 'ip6': lambda p: p.ip is not None and p.ip.version == 6, 'arp': lambda p: p.arp is not None, 'dns': lambda p: p.dns is not None, 'http': lambda p: p.http is not None}

class FilterError(ValueError):
    pass

class _Parser:

    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> str:
        token = self.peek()
        if token is None:
            raise FilterError('unexpected end of filter expression')
        self.pos += 1
        return token

    def accept(self, *values: str) -> bool:
        token = self.peek()
        if token is not None and token.lower() in values:
            self.pos += 1
            return True
        return False

    def expect_value(self, what: str) -> str:
        token = self.peek()
        if token is None or token.lower() in ('and', 'or', 'not', ')'):
            raise FilterError(f"expected {what} after '{self.tokens[self.pos - 1]}'")
        return self.next().strip('"\'')

    def expect_int(self, what: str) -> int:
        raw = self.expect_value(what)
        try:
            return int(raw)
        except ValueError as exc:
            raise FilterError(f"expected a number for {what}, got '{raw}'") from exc

    def parse(self) -> Predicate:
        predicate = self.parse_or()
        if self.peek() is not None:
            raise FilterError(f"unexpected token '{self.peek()}'")
        return predicate

    def parse_or(self) -> Predicate:
        left = self.parse_and()
        while self.accept('or', '||'):
            right = self.parse_and()
            left = (lambda a, b: lambda p: a(p) or b(p))(left, right)
        return left

    def parse_and(self) -> Predicate:
        left = self.parse_not()
        while True:
            if self.accept('and', '&&'):
                right = self.parse_not()
            elif self.peek() is not None and self.peek() not in (')',) and (self.peek().lower() not in ('or', '||')):
                right = self.parse_not()
            else:
                break
            left = (lambda a, b: lambda p: a(p) and b(p))(left, right)
        return left

    def parse_not(self) -> Predicate:
        if self.accept('not', '!'):
            inner = self.parse_not()
            return lambda p: not inner(p)
        return self.parse_primary()

    def parse_primary(self) -> Predicate:
        if self.accept('('):
            inner = self.parse_or()
            if not self.accept(')'):
                raise FilterError('missing closing parenthesis')
            return inner
        return self.parse_predicate()

    def parse_predicate(self) -> Predicate:
        token = self.next().lower()
        if token in PROTOCOL_KEYWORDS:
            return PROTOCOL_KEYWORDS[token]
        direction = None
        if token in ('src', 'dst'):
            direction = token
            nxt = self.peek()
            if nxt is not None and nxt.lower() in ('host', 'net', 'port'):
                token = self.next().lower()
            else:
                token = 'host'
        if token == 'host':
            value = self.expect_value('an address')
            return _host_predicate(value, direction)
        if token == 'net':
            value = self.expect_value('a CIDR network')
            return _net_predicate(value, direction)
        if token in ('port', 'sport', 'dport'):
            if token == 'sport':
                direction = 'src'
            elif token == 'dport':
                direction = 'dst'
            value = self.expect_int('a port')
            return _port_predicate(value, direction)
        if token == 'portrange':
            raw = self.expect_value('a range like 8000-8100')
            if '-' not in raw:
                raise FilterError('portrange needs the form LOW-HIGH')
            low_s, _, high_s = raw.partition('-')
            try:
                low, high = (int(low_s), int(high_s))
            except ValueError as exc:
                raise FilterError(f"bad portrange '{raw}'") from exc
            return lambda p: any((port is not None and low <= port <= high for port in (p.sport, p.dport)))
        if token == 'len':
            op = self.expect_value('a comparison operator')
            number = self.expect_int('a length')
            return _length_predicate(op, number)
        if token in ('tcp-flag', 'flag'):
            flag = self.expect_value('a TCP flag name').upper()
            return lambda p: p.tcp is not None and p.tcp.has(flag)
        if token == 'payload':
            needle = self.expect_value('a search string').lower().encode('utf-8', 'replace')
            return lambda p: needle in p.payload.lower()
        raise FilterError(f"unknown filter keyword '{token}'")

def _host_predicate(value: str, direction: Optional[str]) -> Predicate:
    if direction == 'src':
        return lambda p: p.src_ip == value
    if direction == 'dst':
        return lambda p: p.dst_ip == value
    return lambda p: value in (p.src_ip, p.dst_ip)

def _net_predicate(value: str, direction: Optional[str]) -> Predicate:

    def match(addr: Optional[str]) -> bool:
        return addr is not None and in_network(addr, value)
    if direction == 'src':
        return lambda p: match(p.src_ip)
    if direction == 'dst':
        return lambda p: match(p.dst_ip)
    return lambda p: match(p.src_ip) or match(p.dst_ip)

def _port_predicate(value: int, direction: Optional[str]) -> Predicate:
    if direction == 'src':
        return lambda p: p.sport == value
    if direction == 'dst':
        return lambda p: p.dport == value
    return lambda p: value in (p.sport, p.dport)

def _length_predicate(op: str, number: int) -> Predicate:
    ops = {'>': lambda n: n > number, '>=': lambda n: n >= number, '<': lambda n: n < number, '<=': lambda n: n <= number, '=': lambda n: n == number, '==': lambda n: n == number, '!=': lambda n: n != number}
    if op not in ops:
        raise FilterError(f"unsupported comparison '{op}'")
    test = ops[op]
    return lambda p: test(p.wire_length)

def compile_filter(expression: Optional[str]) -> Predicate:
    if not expression or not expression.strip():
        return lambda p: True
    tokens = TOKEN_RE.findall(expression)
    if not tokens:
        raise FilterError('empty filter expression')
    return _Parser(tokens).parse()
