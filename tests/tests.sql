--#SET TERMINATOR @

/*
 *+----------------------------------------------------------------------+
 *| tests.sql: hashing functions (hashing library for IBM DB2)           |
 *+----------------------------------------------------------------------+
 *| Licensed under the Apache License, Version 2.0 (the "License"); you  |
 *| may not use this file except in compliance with the License. You may |
 *| obtain a copy of the License at                                      |
 *| http://www.apache.org/licenses/LICENSE-2.0                           |
 *|                                                                      |
 *| Unless required by applicable law or agreed to in writing, software  |
 *| distributed under the License is distributed on an "AS IS" BASIS,    |
 *| WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or      |
 *| implied. See the License for the specific language governing         |
 *| permissions and limitations under the License.                       |
 *+----------------------------------------------------------------------+
 *| Author: Andres Gomez Casanova (AngocA)                               |
 *+----------------------------------------------------------------------+
 *| Website: http://mod-auth-ibmdb2.sourceforge.net                      |
 *+----------------------------------------------------------------------+
 */

/**
 * Tests hash procedures and functions.
 *
 * Version: 2014-08-14
 * Author: Andres Gomez Casanova (AngocA)
 */

SET CURRENT SCHEMA DB2_HASH @

CREATE SCHEMA DB2_HASH @

SET PATH = DB2_HASH, DB2UNIT_1, DB2INST1 @

-- Test fixtures
CREATE OR REPLACE PROCEDURE ONE_TIME_SETUP()
 P_ONE_TIME_SETUP: BEGIN
 END P_ONE_TIME_SETUP @

CREATE OR REPLACE PROCEDURE SETUP()
 P_SETUP: BEGIN
 END P_SETUP @

CREATE OR REPLACE PROCEDURE TEAR_DOWN()
 P_TEAR_DOWN: BEGIN
 END P_TEAR_DOWN @

CREATE OR REPLACE PROCEDURE ONE_TIME_TEAR_DOWN()
 P_ONE_TIME_TEAR_DOWN: BEGIN
 END P_ONE_TIME_TEAR_DOWN @

-- Tests
CREATE OR REPLACE PROCEDURE TEST_BCRYPT()
 BEGIN
  DECLARE LOGGER_ID SMALLINT;
  DECLARE STR VARCHAR(120);
  DECLARE LENGTH INT;
  DECLARE STR_1 VARCHAR(60);
  DECLARE STR_2 VARCHAR(60);
  DECLARE EXPECTED INTEGER;
  DECLARE ACTUAL INTEGER;

  CALL LOGGER.GET_LOGGER('HASH.TEST_BCRYPT', LOGGER_ID);

  SET STR = 'Test';
  SET STR_1 = DB2INST1.BCRYPT(STR);
  SET LENGTH = LENGTH(STR_1);
  SET STR_2 = SUBSTR(STR_1, 1, LENGTH - 1) || '@';

  CALL LOGGER.WARN(LOGGER_ID, 'Hash value: ' || STR_1 || ' (' || STR_2 || ')');

  SET EXPECTED = 1;
  SET ACTUAL = DB2INST1.VALIDATE_PW(STR, STR_1);
  CALL DB2UNIT.ASSERT_INT_EQUALS('Original value', EXPECTED, ACTUAL);
  SET EXPECTED = 0;
  SET ACTUAL = DB2INST1.VALIDATE_PW(STR, STR_2);
  CALL DB2UNIT.ASSERT_INT_EQUALS('Modified value', EXPECTED, ACTUAL);
 END @

CREATE OR REPLACE PROCEDURE TEST_PHP_MD5()
 BEGIN
  DECLARE EXPECTED VARCHAR(32);
  DECLARE ACTUAL VARCHAR(32);
  SET EXPECTED = '342df5b036b2f28184536820af6d1caf';
  SET ACTUAL = DB2INST1.PHP_MD5('testpwd');
  CALL DB2UNIT.ASSERT_STRING_EQUALS(EXPECTED, ACTUAL);
 END @

CREATE OR REPLACE PROCEDURE TEST_APR_MD5()
 BEGIN
  DECLARE LOGGER_ID SMALLINT;
  DECLARE STR VARCHAR(120);
  DECLARE LENGTH INT;
  DECLARE STR_1 VARCHAR(37);
  DECLARE STR_2 VARCHAR(37);
  DECLARE EXPECTED INTEGER;
  DECLARE ACTUAL INTEGER;

  CALL LOGGER.GET_LOGGER('HASH.TEST_APR_MD5', LOGGER_ID);

  SET STR = 'Test';
  SET STR_1 = DB2INST1.APR_MD5(STR);
  SET LENGTH = LENGTH(STR_1);
  SET STR_2 = SUBSTR(STR_1, 1, LENGTH - 1) || '@';

  CALL LOGGER.WARN(LOGGER_ID, 'Hash value: ' || STR_1 || ' (' || STR_2 || ')');

  SET EXPECTED = 1;
  SET ACTUAL = DB2INST1.VALIDATE_PW(STR, STR_1);
  CALL DB2UNIT.ASSERT_INT_EQUALS('Original value', EXPECTED, ACTUAL);
  SET EXPECTED = 0;
  SET ACTUAL = DB2INST1.VALIDATE_PW(STR, STR_2);
  CALL DB2UNIT.ASSERT_INT_EQUALS('Modified value', EXPECTED, ACTUAL);
 END @

CREATE OR REPLACE PROCEDURE TEST_APR_CRYPT()
 BEGIN
  DECLARE LOGGER_ID SMALLINT;
  DECLARE STR VARCHAR(120);
  DECLARE LENGTH INT;
  DECLARE STR_1 VARCHAR(13);
  DECLARE STR_2 VARCHAR(13);
  DECLARE EXPECTED INTEGER;
  DECLARE ACTUAL INTEGER;

  CALL LOGGER.GET_LOGGER('HASH.TEST_APR_CRYPT', LOGGER_ID);

  SET STR = 'Test';
  SET STR_1 = DB2INST1.APR_CRYPT(STR);
  SET LENGTH = LENGTH(STR_1);
  SET STR_2 = SUBSTR(STR_1, 1, LENGTH - 1) || '@';

  CALL LOGGER.WARN(LOGGER_ID, 'Hash value: ' || STR_1 || ' (' || STR_2 || ')');

  SET EXPECTED = 1;
  SET ACTUAL = DB2INST1.VALIDATE_PW(STR, STR_1);
  CALL DB2UNIT.ASSERT_INT_EQUALS('Original value', EXPECTED, ACTUAL);
  SET EXPECTED = 0;
  SET ACTUAL = DB2INST1.VALIDATE_PW(STR, STR_2);
  CALL DB2UNIT.ASSERT_INT_EQUALS('Modified value', EXPECTED, ACTUAL);
 END @

CREATE OR REPLACE PROCEDURE TEST_APR_SHA1()
 BEGIN
  DECLARE EXPECTED VARCHAR(33);
  DECLARE ACTUAL VARCHAR(33);
  SET EXPECTED = '{SHA}mO8HWOaqxvmp4Rl1SMgZC3LJWB0=';
  SET ACTUAL = DB2INST1.APR_SHA1('testpwd');
  CALL DB2UNIT.ASSERT_STRING_EQUALS(EXPECTED, ACTUAL);
 END @

CREATE OR REPLACE PROCEDURE TEST_APR_SHA256()
 BEGIN
  DECLARE EXPECTED VARCHAR(52);
  DECLARE ACTUAL VARCHAR(52);
  SET EXPECTED = '{SHA256}qFtqIIE8Maixs/NhjaeWJxyaopOz+AmHMFOyGuxQEIc=';
  SET ACTUAL = DB2INST1.APR_SHA256('testpwd');
  CALL DB2UNIT.ASSERT_STRING_EQUALS(EXPECTED, ACTUAL);
 END @

CREATE OR REPLACE PROCEDURE TEST_VALIDATE_PW()
 BEGIN
  DECLARE EXPECTED INTEGER;
  DECLARE ACTUAL INTEGER;
  SET EXPECTED = 1;
  SET ACTUAL = DB2INST1.VALIDATE_PW('testpwd', 'cqs7uOvz8KBlk');
  CALL DB2UNIT.ASSERT_INT_EQUALS(EXPECTED, ACTUAL);
 END @

CALL DB2UNIT.REGISTER_MESSAGE(CURRENT SCHEMA) @
  

