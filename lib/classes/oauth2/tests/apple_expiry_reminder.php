<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

namespace core\oauth2\tests;

/**
 * External core oauth2 API tests.
 *
 * @package    core
 * @copyright  2017 Damyon Wiese
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 *
 * @covers \core\oauth2\apple_expiry_reminder
 */
class apple_expiry_reminder extends \advanced_testcase {

    /**
     * @var object $appleissuer New appleissuer created to test the expiry reminder email.
     */
    protected $appleissuer = null;
    /**
     * Called before every test.
     */
    public function setUp(): void {
        parent::setUp();
        $classname = 'core\\oauth2\\service\\apple';
        if (class_exists($classname)) {
            $issuer = $classname::init();
            $issuer->create();
            $this->appleissuer = $issuer;

        }
    }
    /**
     * Test creating a user via the send apple expiry reminder email method.
     *
     * @covers  \core\oauth2\apple_expiry_reminder::send_service_expiry_email
     */
    public function test_send_apple_expiry_reminder_email(): void {

        $this->resetAfterTest();
        $this->setAdminUser();
        
        $expdates = [strtotime(date('Y-m-d', strtotime('-1 week'))), strtotime(date('Y-m-d', strtotime('+1 week')))];

        foreach ($expdates as $expdate) {

            // Set sample data to generate the secret key.
            $tokeninfo = [];
            $tokeninfo['iat'] = 'apple1';
            $tokeninfo['exp'] = $expdate;
            $tokeninfo['aud'] = 'https://appleid.apple.com';
            $tokeninfo['sub'] = 'apple1';

            // Generate sample secret ke.y
            $secretkey = $this->getDataGenerator()->generate_sample_secretkey($tokeninfo);

            // Set client id to issuer object.
            $this->appleissuer->set('clientid', 'apple1');

            // Set client secret to issuer object.
            $this->appleissuer->set('clientsecret', $secretkey);

            // Check service expiry email sent or not.
            $ismailsent = (new \core\oauth2\apple_expiry_reminder)->send_expiry_reminder_email($this->appleissuer);

            // Confirm expiry email sent.
            if($ismailsent) {
                $this->assertEquals(true, $ismailsent);
            }

            // Confirm expiry email is not sent.
            if(!$ismailsent) {
                $this->assertEquals(false, $ismailsent);
            }

        }

    }
}
