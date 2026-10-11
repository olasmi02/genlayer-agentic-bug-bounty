"""
Pytest configuration and GenLayer Direct Mode test harness.
Provides fixtures and cheatcodes mirroring GenLayer Direct Mode (gltest / genlayer-test).
"""

import sys
import types
import json
import re
import typing
from dataclasses import dataclass
import pytest


# -----------------------------------------------------------------------------
# GENLAYER RUNTIME EMULATOR (In-memory Direct Mode)
# -----------------------------------------------------------------------------

class Address:
    def __init__(self, val):
        if isinstance(val, Address):
            self._hex = val._hex
        elif isinstance(val, bytes):
            self._hex = "0x" + val.hex()
        elif isinstance(val, str):
            val = val.strip()
            if not val.startswith("0x"):
                val = "0x" + val
            self._hex = val.lower()
        else:
            raise ValueError(f"Cannot construct Address from {val}")

    @property
    def as_hex(self) -> str:
        return self._hex

    @property
    def as_bytes(self) -> bytes:
        raw = self._hex[2:] if self._hex.startswith("0x") else self._hex
        return bytes.fromhex(raw.zfill(40))

    @property
    def as_b64(self) -> str:
        import base64
        return base64.b64encode(self.as_bytes).decode("ascii")

    def __eq__(self, other):
        if isinstance(other, Address):
            return self._hex.lower() == other._hex.lower()
        if isinstance(other, str):
            return self._hex.lower() == other.lower()
        return False

    def __hash__(self):
        return hash(self._hex.lower())

    def __repr__(self):
        return f"Address('{self._hex}')"


class u256(int):
    def __new__(cls, val=0):
        val_int = int(val)
        if val_int < 0:
            raise ValueError("u256 cannot be negative")
        return super().__new__(cls, val_int)

class u64(int):
    def __new__(cls, val=0):
        val_int = int(val)
        if val_int < 0:
            raise ValueError("u64 cannot be negative")
        return super().__new__(cls, val_int)

class u128(int):
    pass

class u32(int):
    pass

class u16(int):
    pass

class u8(int):
    pass

class i64(int):
    pass

class i32(int):
    pass

class bigint(int):
    pass


class TreeMap(dict):
    """GenVM persistent sorted tree map."""
    pass


class DynArray(list):
    """GenVM persistent dynamic array."""
    pass


def allow_storage(cls):
    """GenVM storage decorator."""
    return cls


class WebResponse:
    def __init__(self, body: str, status: int = 200):
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.status = status


class UserError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class VMError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class Return:
    def __init__(self, calldata):
        self.calldata = calldata


class GLVM:
    UserError = UserError
    VMError = VMError
    Return = Return

    def __init__(self, direct_vm):
        self._direct_vm = direct_vm

    def run_nondet_unsafe(self, leader_fn, validator_fn):
        return self._direct_vm.execute_consensus(leader_fn, validator_fn)


class DirectVMSimulator:
    """
    Direct Mode simulator supporting cheatcodes:
    - prank / sender control
    - mock_web
    - mock_llm
    - consensus execution
    - timestamp control
    - balance tracking
    """
    def __init__(self):
        self.sender = Address("0x0000000000000000000000000000000000000001")
        self.value = u256(0)
        self.balances = {}  # Address -> int
        self.web_mocks = []
        self.llm_mocks = []
        self.validator_mode = False
        self.validator_llm_mocks = []
        self.validator_web_mocks = []
        self.timestamp = u64(1735689600)  # Default timestamp: 2025-01-01 00:00:00 UTC

    def mock_web(self, url_pattern: str, response_body: str, status: int = 200, for_validator: bool = False):
        target = self.validator_web_mocks if for_validator else self.web_mocks
        target.append((re.compile(url_pattern), WebResponse(response_body, status)))

    def mock_llm(self, pattern: str, response: typing.Any, for_validator: bool = False):
        target = self.validator_llm_mocks if for_validator else self.llm_mocks
        target.append((re.compile(pattern, re.DOTALL), response))

    def get_web(self, url: str) -> WebResponse:
        mocks = self.validator_web_mocks if self.validator_mode and self.validator_web_mocks else self.web_mocks
        for pattern, resp in reversed(mocks):
            if pattern.search(url):
                return resp
        # Default mock response if not explicitly matched
        return WebResponse('{"scope": ["contracts/Vault.sol", "contracts/Token.sol"]}', 200)

    def exec_prompt(self, prompt: str, response_format: str = None):
        mocks = self.validator_llm_mocks if self.validator_mode and self.validator_llm_mocks else self.llm_mocks
        for pattern, resp in reversed(mocks):
            if pattern.search(prompt):
                return resp
        raise RuntimeError(f"No mock found for prompt: {prompt[:100]}...")

    def execute_consensus(self, leader_fn, validator_fn):
        # 1. Run leader
        self.validator_mode = False
        try:
            leader_val = leader_fn()
            leader_res = leader_val
        except Exception as e:
            leader_res = e

        # 2. Run validator
        self.validator_mode = True
        try:
            agreed = validator_fn(leader_res)
        finally:
            self.validator_mode = False

        if agreed:
            if isinstance(leader_res, Exception):
                raise leader_res
            return leader_res
        else:
            raise UserError("[CONSENSUS_DISAGREEMENT] Validator rejected leader proposal")

    def prank(self, sender: Address, value: int = 0):
        class PrankContext:
            def __init__(ctx, sim, new_sender, new_val):
                ctx.sim = sim
                ctx.new_sender = new_sender
                ctx.new_val = u256(new_val)
                ctx.old_sender = None
                ctx.old_val = None

            def __enter__(ctx):
                ctx.old_sender = ctx.sim.sender
                ctx.old_val = ctx.sim.value
                ctx.sim.sender = ctx.new_sender
                ctx.sim.value = ctx.new_val

            def __exit__(ctx, *args):
                ctx.sim.sender = ctx.old_sender
                ctx.sim.value = ctx.old_val

        return PrankContext(self, sender, value)


# Build the mock 'genlayer' module
direct_sim = DirectVMSimulator()

class ContractProxyMock:
    def __init__(self, target_addr: Address, sim: DirectVMSimulator):
        self.target_addr = target_addr
        self.sim = sim

    def emit_transfer(self, *, value: u256) -> None:
        val = int(value)
        self.sim.balances[self.target_addr] = self.sim.balances.get(self.target_addr, 0) + val


def get_contract_at(addr: Address):
    return ContractProxyMock(addr, direct_sim)


class MessageProxy:
    @property
    def sender_address(self) -> Address:
        return direct_sim.sender

    @property
    def value(self) -> u256:
        return direct_sim.value


class BlockProxy:
    @property
    def timestamp(self) -> u64:
        return direct_sim.timestamp


class NondetWebProxy:
    def get(self, url: str):
        return direct_sim.get_web(url)


class NondetProxy:
    web = NondetWebProxy()

    @staticmethod
    def exec_prompt(prompt: str, response_format: str = None):
        return direct_sim.exec_prompt(prompt, response_format)


class PublicDecorators:
    @staticmethod
    def write(fn):
        return fn

    @staticmethod
    def view(fn):
        return fn


class GLContract:
    def __new__(cls, *args, **kwargs):
        inst = super().__new__(cls)
        for attr, type_hint in getattr(cls, "__annotations__", {}).items():
            hint_str = str(type_hint)
            if "TreeMap" in hint_str:
                setattr(inst, attr, TreeMap())
            elif "DynArray" in hint_str:
                setattr(inst, attr, DynArray())
        return inst


class GLProxy:
    Contract = GLContract
    public = PublicDecorators()
    message = MessageProxy()
    block = BlockProxy()
    nondet = NondetProxy()
    vm = GLVM(direct_sim)
    get_contract_at = staticmethod(get_contract_at)


# Inject into sys.modules before contract import
gl_module = types.ModuleType("genlayer")
gl_module.Address = Address
gl_module.u256 = u256
gl_module.u128 = u128
gl_module.u64 = u64
gl_module.u32 = u32
gl_module.u16 = u16
gl_module.u8 = u8
gl_module.i64 = i64
gl_module.i32 = i32
gl_module.bigint = bigint
gl_module.TreeMap = TreeMap
gl_module.DynArray = DynArray
gl_module.allow_storage = allow_storage
gl_module.gl = GLProxy

sys.modules["genlayer"] = gl_module


# -----------------------------------------------------------------------------
# PYTEST FIXTURES
# -----------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_direct_vm():
    """Resets simulator state before every test."""
    direct_sim.sender = Address("0x0000000000000000000000000000000000000001")
    direct_sim.value = u256(0)
    direct_sim.balances.clear()
    direct_sim.web_mocks.clear()
    direct_sim.llm_mocks.clear()
    direct_sim.validator_mode = False
    direct_sim.validator_llm_mocks.clear()
    direct_sim.validator_web_mocks.clear()
    direct_sim.timestamp = u64(1735689600)
    yield direct_sim


@pytest.fixture
def direct_vm():
    return direct_sim


@pytest.fixture
def treasury_address():
    return Address("0x1111111111111111111111111111111111111111")


@pytest.fixture
def sponsor_address():
    return Address("0x2222222222222222222222222222222222222222")


@pytest.fixture
def researcher_address():
    return Address("0x3333333333333333333333333333333333333333")


@pytest.fixture
def attacker_address():
    return Address("0x9999999999999999999999999999999999999999")
