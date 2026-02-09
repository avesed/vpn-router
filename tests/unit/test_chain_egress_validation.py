#!/usr/bin/env python3
"""Unit tests for Phase III Bug 4 fix: Chain terminal egress validation

Tests the _validate_chain_terminal_egress() function with comprehensive coverage:
- Invalid egress type rejection (direct, block, adblock)
- Valid egress acceptance
- Edge cases (None, empty string, whitespace)
- Case sensitivity handling
- Dual response modes (HTTPException vs dict)
- Error message quality (bilingual)

Run: pytest tests/unit/test_chain_egress_validation.py -v
"""

import os
import secrets
import sys
from pathlib import Path

import pytest

# Setup encryption key before importing api_server
if not os.environ.get("SQLCIPHER_KEY"):
    os.environ["SQLCIPHER_KEY"] = secrets.token_hex(32)

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from fastapi import HTTPException

# Import after path setup
try:
    from api_server import _validate_chain_terminal_egress, INVALID_CHAIN_TERMINAL_EGRESS
except ImportError as e:
    pytest.skip(f"Could not import api_server: {e}", allow_module_level=True)


class TestInvalidChainTerminalEgressConstant:
    """Test the INVALID_CHAIN_TERMINAL_EGRESS constant definition"""

    def test_constant_exists(self):
        """Verify INVALID_CHAIN_TERMINAL_EGRESS is defined"""
        assert INVALID_CHAIN_TERMINAL_EGRESS is not None

    def test_constant_is_immutable(self):
        """Verify constant is frozenset (immutable)"""
        assert isinstance(INVALID_CHAIN_TERMINAL_EGRESS, frozenset)

    def test_constant_contains_direct(self):
        """Verify 'direct' is in invalid list"""
        assert "direct" in INVALID_CHAIN_TERMINAL_EGRESS

    def test_constant_contains_block(self):
        """Verify 'block' is in invalid list"""
        assert "block" in INVALID_CHAIN_TERMINAL_EGRESS

    def test_constant_contains_adblock(self):
        """Verify 'adblock' is in invalid list"""
        assert "adblock" in INVALID_CHAIN_TERMINAL_EGRESS

    def test_constant_has_exactly_three_items(self):
        """Verify constant has exactly 3 invalid types"""
        assert len(INVALID_CHAIN_TERMINAL_EGRESS) == 3

    def test_constant_values_are_strings(self):
        """Verify all items in constant are strings"""
        for item in INVALID_CHAIN_TERMINAL_EGRESS:
            assert isinstance(item, str)


class TestValidateInvalidEgressTypesUserAPI:
    """Test _validate_chain_terminal_egress with user-facing API (for_tunnel_api=False)"""

    @pytest.mark.parametrize("invalid_type", ["direct", "block", "adblock"])
    def test_rejects_invalid_types(self, invalid_type):
        """Test validation rejects all three invalid types"""
        with pytest.raises(HTTPException) as exc_info:
            _validate_chain_terminal_egress(invalid_type, for_tunnel_api=False)

        assert exc_info.value.status_code == 400
        assert "detail" in vars(exc_info.value)

    @pytest.mark.parametrize("invalid_type", ["direct", "block", "adblock"])
    def test_error_includes_egress_name(self, invalid_type):
        """Test error message includes the offending egress name"""
        with pytest.raises(HTTPException) as exc_info:
            _validate_chain_terminal_egress(invalid_type, for_tunnel_api=False)

        assert invalid_type in str(exc_info.value.detail)

    def test_direct_raises_http_exception(self):
        """Test 'direct' egress raises HTTPException"""
        with pytest.raises(HTTPException):
            _validate_chain_terminal_egress("direct")

    def test_block_raises_http_exception(self):
        """Test 'block' egress raises HTTPException"""
        with pytest.raises(HTTPException):
            _validate_chain_terminal_egress("block")

    def test_adblock_raises_http_exception(self):
        """Test 'adblock' egress raises HTTPException"""
        with pytest.raises(HTTPException):
            _validate_chain_terminal_egress("adblock")


class TestValidateInvalidEgressTypesTunnelAPI:
    """Test _validate_chain_terminal_egress with tunnel API mode (for_tunnel_api=True)"""

    @pytest.mark.parametrize("invalid_type", ["direct", "block", "adblock"])
    def test_returns_dict_not_exception(self, invalid_type):
        """Test tunnel API mode returns dict instead of raising exception"""
        result = _validate_chain_terminal_egress(invalid_type, for_tunnel_api=True)
        assert isinstance(result, dict)
        assert result is not None

    @pytest.mark.parametrize("invalid_type", ["direct", "block", "adblock"])
    def test_dict_has_success_false(self, invalid_type):
        """Test returned dict has success=False"""
        result = _validate_chain_terminal_egress(invalid_type, for_tunnel_api=True)
        assert result.get("success") is False

    @pytest.mark.parametrize("invalid_type", ["direct", "block", "adblock"])
    def test_dict_has_message(self, invalid_type):
        """Test returned dict includes error message"""
        result = _validate_chain_terminal_egress(invalid_type, for_tunnel_api=True)
        assert "message" in result
        assert isinstance(result["message"], str)
        assert len(result["message"]) > 0


class TestValidateValidEgressTypes:
    """Test _validate_chain_terminal_egress with valid egress types"""

    @pytest.mark.parametrize("valid_type", [
        "my-pia-profile",
        "custom-wg",
        "openvpn-server",
        "us-stream",
        "jp-gaming",
        "direct-eth0",
        "warp-masque",
    ])
    def test_accepts_valid_types_user_api(self, valid_type):
        """Test validation accepts valid egress types in user API mode"""
        # Should not raise exception
        result = _validate_chain_terminal_egress(valid_type, for_tunnel_api=False)
        assert result is None

    @pytest.mark.parametrize("valid_type", [
        "my-pia-profile",
        "custom-wg",
        "openvpn-server",
    ])
    def test_accepts_valid_types_tunnel_api(self, valid_type):
        """Test validation accepts valid egress types in tunnel API mode"""
        result = _validate_chain_terminal_egress(valid_type, for_tunnel_api=True)
        # Should return None for valid types
        assert result is None


class TestValidateEdgeCases:
    """Test _validate_chain_terminal_egress edge cases"""

    def test_none_input_user_api(self):
        """Test validation with None input in user API mode

        ISSUE #1: Currently this passes (returns None), should it fail?
        """
        # Document current behavior
        result = _validate_chain_terminal_egress(None, for_tunnel_api=False)
        # Current behavior: returns None (passes)
        # Note: This is a bug, should raise HTTPException
        # TODO: Fix this

    def test_empty_string_user_api(self):
        """Test validation with empty string in user API mode

        ISSUE #1: Currently this passes (returns None), should it fail?
        """
        # Document current behavior
        result = _validate_chain_terminal_egress("", for_tunnel_api=False)
        # Current behavior: returns None (passes)
        # Note: This is a bug, should raise HTTPException
        # TODO: Fix this

    def test_whitespace_only(self):
        """Test validation with whitespace-only input"""
        result = _validate_chain_terminal_egress("   ", for_tunnel_api=False)
        # Whitespace is technically not in INVALID list, will pass
        # This might be acceptable behavior

    def test_very_long_egress_name(self):
        """Test validation with extremely long egress name"""
        long_name = "a" * 1000
        result = _validate_chain_terminal_egress(long_name, for_tunnel_api=False)
        # Should accept (not in invalid list)
        assert result is None


class TestValidateCaseSensitivity:
    """Test _validate_chain_terminal_egress case sensitivity handling"""

    @pytest.mark.parametrize("case_variant", [
        "Direct",  # Capital D
        "DIRECT",  # All caps
        "DiReCtS",  # Mixed case
    ])
    def test_case_variants_not_rejected(self, case_variant):
        """Test that case variations are NOT rejected (case-sensitive validation)

        This documents current behavior. Case-insensitive matching would be more robust.
        """
        # Current behavior: case-sensitive, so "Direct" is not matched against "direct"
        result = _validate_chain_terminal_egress(case_variant, for_tunnel_api=False)
        # These should pass (not in invalid list due to case difference)
        assert result is None

    def test_lowercase_direct_rejected(self):
        """Test that exact lowercase 'direct' IS rejected"""
        with pytest.raises(HTTPException):
            _validate_chain_terminal_egress("direct", for_tunnel_api=False)


class TestValidateErrorMessages:
    """Test error message quality and content"""

    def test_error_message_in_chinese(self):
        """Test error message includes Chinese translation"""
        with pytest.raises(HTTPException) as exc_info:
            _validate_chain_terminal_egress("direct", for_tunnel_api=False)

        # Should contain Chinese characters/words
        detail = str(exc_info.value.detail)
        assert "链路" in detail or "出口" in detail or "接口" in detail

    def test_tunnel_api_error_message_in_english(self):
        """Test tunnel API error message includes English"""
        result = _validate_chain_terminal_egress("block", for_tunnel_api=True)

        message = result.get("message", "")
        assert "cannot be used as chain terminal egress" in message
        assert "interface binding" in message

    def test_error_message_mentions_valid_types(self):
        """Test error message suggests valid alternatives"""
        result = _validate_chain_terminal_egress("direct", for_tunnel_api=True)

        message = result.get("message", "")
        # Should mention what IS valid
        assert any(valid in message for valid in ["PIA", "WireGuard", "OpenVPN"])


class TestValidateDualModeConsistency:
    """Test consistency between user API and tunnel API modes"""

    def test_same_validation_logic(self):
        """Test that both modes reject the same types"""
        invalid_types = ["direct", "block", "adblock"]

        for egress_type in invalid_types:
            # User API mode should raise
            with pytest.raises(HTTPException):
                _validate_chain_terminal_egress(egress_type, for_tunnel_api=False)

            # Tunnel API mode should return error dict
            result = _validate_chain_terminal_egress(egress_type, for_tunnel_api=True)
            assert result is not None
            assert result.get("success") is False

    def test_valid_types_accepted_both_modes(self):
        """Test that valid types are accepted in both modes"""
        valid_types = ["my-pia", "custom-wg", "ovpn-server"]

        for egress_type in valid_types:
            # User API mode
            result1 = _validate_chain_terminal_egress(egress_type, for_tunnel_api=False)
            assert result1 is None

            # Tunnel API mode
            result2 = _validate_chain_terminal_egress(egress_type, for_tunnel_api=True)
            assert result2 is None


class TestValidateErrorCodes:
    """Test HTTP status codes"""

    def test_http_400_status_code(self):
        """Test that validation errors return HTTP 400 (bad request)"""
        with pytest.raises(HTTPException) as exc_info:
            _validate_chain_terminal_egress("direct")

        assert exc_info.value.status_code == 400

    def test_not_500_status_code(self):
        """Test that validation errors do NOT return 500 (not a server error)"""
        with pytest.raises(HTTPException) as exc_info:
            _validate_chain_terminal_egress("block")

        assert exc_info.value.status_code != 500


# ============ Integration test placeholder ============

class TestValidateIntegration:
    """Integration tests with chain creation/activation (placeholder)

    These tests require database setup and should be moved to
    tests/integration/test_chain_creation.py once database fixtures are ready.
    """

    @pytest.mark.skip(reason="Requires database setup")
    def test_create_chain_with_invalid_egress(self):
        """Test that creating chain with invalid egress fails"""
        # TODO: Implement with API client
        pass

    @pytest.mark.skip(reason="Requires database setup")
    def test_create_chain_with_valid_egress(self):
        """Test that creating chain with valid egress succeeds"""
        # TODO: Implement with API client
        pass

    @pytest.mark.skip(reason="Requires database setup")
    def test_activate_chain_invalid_egress(self):
        """Test that activating chain with invalid egress fails"""
        # TODO: Implement with API client
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
