#!/usr/bin/env python3

# py3 explicitly for mock_open and friends
#

import unittest
from unittest.mock import patch, mock_open
from libpius.state import SignState

class TestFileConversion(unittest.TestCase):
  kSAMPLE = {
      'one': {'OUTBOUND': 'SIGNED', 'INBOUND': None},
      'two': {'OUTBOUND': 'SIGNED', 'INBOUND': None},
      'three': {'OUTBOUND': 'SIGNED', 'INBOUND': None},
  }

  def setUp(self):
    self.state = SignState()


  def test_convert_from_v1(self):
    self.assertEqual(
        self.state.convert_from_v1("one\ntwo\nthree"),
        self.kSAMPLE,
    )

  def test_convert_from_v2(self):
    self.assertEqual(
        self.state.convert_from_v2({
          'one': 'SIGNED',
          'two': 'SIGNED',
          'three': 'SIGNED',
          }),
        self.kSAMPLE,
    )

  @patch('libpius.state.SignState.write_file', create=True)
  def test_read_v1_writes_v3(self, write_file):
    data = "one\ntwo\nthree"
    new = {'four': {'OUTBOUND': 'SIGNED', 'INBOUND': None}}
    with patch('libpius.state.open', mock_open(read_data=data), create=True) as m:
        with patch('libpius.state.os.path.exists', return_value=True) as p:
            self.state.store_signed_keys(new)
    temp = self.kSAMPLE.copy()
    temp.update(new)
    temp.update(SignState.kFILE_METADATA)
    write_file.assert_called_once_with(temp)

  @patch('libpius.state.SignState.write_file', create=True)
  def test_read_v2_writes_v3(self, write_file):
    data = '{"one":"SIGNED","two":"SIGNED","three":"SIGNED"}'
    new = {'four': {'OUTBOUND': 'SIGNED', 'INBOUND': None}}
    with patch('libpius.state.open', mock_open(read_data=data)) as m:
        with patch('libpius.state.os.path.exists', return_value=True) as p:
            self.state.store_signed_keys(new)
    temp = self.kSAMPLE.copy()
    temp.update(new)
    temp.update(SignState.kFILE_METADATA)
    write_file.assert_called_once_with(temp)

  @patch('libpius.state.SignState.write_file', create=True)
  def test_read_empty_writes_v3_with_new_data(self, write_file):
    data = '{}'
    new = {'four': {'OUTBOUND': 'SIGNED', 'INBOUND': None}}
    with patch('libpius.state.open', mock_open(read_data=data)) as m:
      self.state.store_signed_keys(new)
    temp = new.copy()
    temp.update(SignState.kFILE_METADATA)
    write_file.assert_called_once_with(temp)

  @patch('libpius.state.SignState.write_file', create=True)
  def test_read_empty_writes_v3_with_no_new_data(self, write_file):
    data = '{}'
    new = {}
    with patch('libpius.state.open', mock_open(read_data=data)) as m:
      self.state.store_signed_keys(new)
    temp = new.copy()
    temp.update(SignState.kFILE_METADATA)
    write_file.assert_called_once_with(temp)
