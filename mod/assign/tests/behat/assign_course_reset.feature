@mod @mod_assign
Feature: Assign reset
  In order to reuse past Assignss
  As a teacher
  I need to remove all previous data.

  Background:
    Given the following "users" exist:
      | username | firstname | lastname | email |
      | teacher1 | Tina | Teacher1 | teacher1@example.com |
      | student1 | Sam1 | Student1 | student1@example.com |
      | student2 | Sam2 | Student2 | student2@example.com |
    And the following "courses" exist:
      | fullname | shortname | category |
      | Course 1 | C1 | 0 |
    And the following "course enrolments" exist:
      | user | course | role |
      | teacher1 | C1 | editingteacher |
      | student1 | C1 | student |
      | student2 | C1 | student |
    And the following "groups" exist:
      | name    | course | idnumber |
      | Group 1 | C1     | G1       |
      | Group 2 | C1     | G2       |
    And the following "activity" exists:
      | activity                                      | assign                  |
      | course                                        | C1                      |
      | name                                          | Test assignment name    |
      | intro                                         | Submit your online text |
      | assignsubmission_onlinetext_enabled           | 1                       |
      | assignsubmission_onlinetext_wordlimit_enabled | 1                       |
      | assignsubmission_onlinetext_wordlimit         | 10                      |
      | assignsubmission_file_enabled                 | 0                       |
      | submissiondrafts                              | 0                       |

  Scenario: Use course reset to clear all attempt data
    Given the following "mod_assign > submissions" exist:
      | assign                | user      | onlinetext                       |
      | Test assignment name  | student1  | I'm the student first submission |
    And I am on the "Test assignment name" Activity page logged in as student1
    And I should see "Submitted for grading"
    And I should see "I'm the student first submission"
    And I should see "Not graded"
    And I log out

    And I am on the "Test assignment name" Activity page logged in as teacher1
    And I navigate to "Submissions" in current page administration
    And I should see "Submitted for grading"
    When I am on the "Course 1" "reset" page
    And I set the following fields to these values:
        | All submissions | 1  |
    And I press "Reset course"
    And I press "Continue"
    And I am on the "Test assignment name" Activity page
    And I navigate to "Submissions" in current page administration
    Then I should not see "Submitted for grading"

  @javascript
  Scenario: Use course reset to remove user overrides
    And I am on the "Test assignment name" Activity page logged in as teacher1
    And I navigate to "Overrides" in current page administration
    And I press "Add user override"
    And I set the following fields to these values:
        | Override user    | Student1  |
        | id_duedate_enabled | 1 |
        | duedate[day]       | 1 |
        | duedate[month]     | January |
        | duedate[year]      | 2020 |
        | duedate[hour]      | 08 |
        | duedate[minute]    | 00 |
    And I press "Save"
    And I should see "Sam1 Student1"
    When I am on the "Course 1" "reset" page
    And I press "Deselect all"
    And I set the following fields to these values:
        | All user overrides | 1  |
    And I press "Reset course"
    And I click on "Reset course" "button" in the "Reset course?" "dialogue"
    And I press "Continue"
    And I am on "Course 1" course homepage
    And I click on "Test assignment name" "link" in the "region-main" "region"
    And I navigate to "Overrides" in current page administration
    Then I should not see "Sam1 Student1"

  Scenario: Use course reset to remove group overrides.
    When I am on the "Test assignment name" Activity page logged in as teacher1
    And I navigate to "Overrides" in current page administration
    And I select "Group overrides" from the "jump" singleselect
    And I press "Add group override"
    And I set the following fields to these values:
        | Override group   | Group 1  |
        | id_duedate_enabled | 1 |
        | duedate[day]       | 1 |
        | duedate[month]     | January |
        | duedate[year]      | 2020 |
        | duedate[hour]      | 08 |
        | duedate[minute]    | 00 |
    And I press "Save"
    And I should see "Group 1"
    And I am on the "Course 1" "reset" page
    And I set the following fields to these values:
        | All group overrides | 1  |
    And I press "Reset course"
    And I press "Continue"
    And I am on the "Test assignment name" Activity page
    And I navigate to "Overrides" in current page administration
    And I select "Group overrides" from the "jump" singleselect
    Then I should not see "Group 1"

  Scenario: Use course reset to reset blind marking assignment.
    When I am on the "Test assignment name" Activity page logged in as teacher1
    And I navigate to "Settings" in current page administration
    And I set the following fields to these values:
        | blindmarking | 1 |
    And I press "Save"
    When I am on the "Test assignment name" Activity page
    And I navigate to "Submissions" in current page administration
    And I choose the "Reveal student identities" item in the "Actions" action menu
    And I press "Continue"
    And I should see "Sam1 Student1"
    When I am on the "Course 1" "reset" page
    And I set the following fields to these values:
        | All submissions | 1 |
    And I press "Reset course"
    And I press "Continue"
    And I am on the "Test assignment name" Activity page
    And I navigate to "Submissions" in current page administration
    Then I should not see "Sam1 Student1"
