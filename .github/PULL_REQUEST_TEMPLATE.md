## Pull Request Checklist

- [ ] **Code Review**
  - [ ] **General**
    - [ ] Is the code well-structured, consistent in style, and consistently formatted?
    - [ ] Confirm that all procedures called appropriately, and all code is reachable and utilizede?
    - [ ] Confirm that all stubs and test routines have been removed from the codebase?
    - [ ] Confirm that code has been optimized by leveraging external reusable components and library functions where applicable?
    - [ ] Confirm that the blocks of repeated code have been successfully condensed into single, reusable procedures?
    - [ ] Is storage for variable  / file used efficiently  and released when not needed?
    - [ ] Confirm that Modules have been reviewed and streamlined to ensure they are well-structured and appropriately divided into manageable routines.
    - [ ] Does the Code has been verified using specialized tools to ensure accuracy and adherence to standards
  - [ ] **Documentation**
    - [ ] Is the code clearly and adequately documented with an easy-to-maintain commenting style?
    - [ ] Are all comments consistent with the code?
  - [ ] **Variables**
    - [ ] Are all variables properly defined with meaningful, consistent, and clear names?
    - [ ] Do all assigned variables have proper type consistency or casting?
    - [ ] Are variables initiatialized?
    - [ ] Are there any redundant or unused variables?
  - [ ] **Arithmetic Operators**
    - [ ] Does the code avoid comparing floating-point numbers for equality?
    - [ ] Does the code systematically prevent rounding errors?
    - [ ] Does the code avoid additions and subtractions on numbers with greatly different magnitudes?
    - [ ] Are divisors tested for zero or noise?
  - [ ] **Loops and Branches**
    - [ ] Are all loops, branches, and logic constructs complete, correct, and properly nested?
    - [ ] Are the most common cases tested first in IF- -ELSEIF chains?
    - [ ] Are all cases covered in an IF- -ELSEIF or CASE block, including ELSE or DEFAULT clauses?
    - [ ] Does every case statement have a default?
    - [ ] Are loop termination conditions obvious and achievable? Ex. For do…while loop, exit criteria should be know clearly to reduce risk of infinite loops?
    - [ ] Are indexes or subscripts properly initialized, just prior to the loop?
    - [ ] Can any statements that are enclosed within loops be placed outside the loops?
    - [ ] Does the code in the loop avoid manipulating the index variable or using it upon exit from the loop?
  - [ ] **Defensive Programming**
    - [ ]  Are imported data and input arguments checked for validity and completeness?
    - [ ]  Are all output variables assigned?
    - [ ]  Are the correct data operated on in each statement?
    - [ ]  Is every memory allocation deallocated?
    - [ ]  Are timeouts or error traps used for external device accesses?
    - [ ]  Are files / variables checked for existence before attempting to access them?
    - [ ]  Are all files and devices are left in the correct state upon program termination?
  - [ ] **Design Implementaion**
    - [ ] Does the code completely and correctly implement the design (HLD & LLD)?
  - [ ] **Automotive Projects Specific (ASPICE derivation)**
    - [ ] Are MISRA specific coding standard / guidelines (relevant version, as applicable for the project) followed appropriately ?
    - [ ] Is static analysis of code performed successfully as per the defined criteria in the project plan?
    - [ ] Are dynamic parameters(eg. Calibration, state machines, etc) considered?
  - [ ] **Traceability**
    - [ ] Does the Traceability has sufficient information to maintain all the work products relationship as per the project plan ?
    - [ ] Is traceability between HLD/LLD to Software Code established?
    - [ ] "Is the referal  question answer records traced appropriately? 
          (the clarifications for any queries received from customer should be documented and traced)
  - [ ] **Saftey Checks**
    - [ ] Does the Entry and Exit point of function is verified?
          Note: Function should be called from one place and return once."
    - [ ] Confirm no Dynamic Variables or Object are used?
          Note: For best practice Dynamic variables should not be used"
    - [ ] Are variables explictly initiatialized?
          Note: Global and local variables"
    - [ ] Confirm that the same variable name are not used more than once in the Software.
    - [ ] Confirm that, No pointer are used.
          Note: For best practice Pointers should not be used"
    - [ ] Confirm that, there is implict type conversion used.
          Note: Direct assignment of one data type to another is prohibited. If needed used Explict Type cast"
    - [ ] Does the Data and Control flow validated?
          Note: All function call and data flow between function should happen intended by Incespetion/Static code Analysis"
    - [ ] Confirm that there are no Unconditional jump statements are used.
          Note: Goto statement
- [ ] **Unit Test Plan Review**
  - [ ] **General**
    - [ ]  Does the test plan specify the objectives, entry criteria and exit criteria for testing?
    - [ ]  Does the test plan identify and specify all equipment, software tools and any other resources required for testing? (Or provide reference to where these are specified.)
    - [ ]  Does the test plan specify the test environment - hardware, software, OS, simulation, etc?
    - [ ]  Have you considered optimization of resources (hardware, software, OS etc)?
    - [ ]  Are risks associated with testing identified in the test plan or in the project plan?
    - [ ]  Are dependencies for the test activity identified in the test plan or in the project plan?
    - [ ]  Does the test plan identify what test tools, scripts, batch files, etc. are to be developed for testing?
    - [ ]  Are all required test topologies identified and described in the test plan?
    - [ ]  Does the test plan (or project plan) specify how faults detected by testing are recorded?\
    - [ ]  Does the test plan specify how regression testing will be done?
    - [ ]  Does the test plan (or the project plan) identify how test records will be maintained?
    - [ ]  Is the minimum acceptable test coverage for each module stated quantitatively in the test plan?
    - [ ]  Has the updated RTM been sent as part of UTP for review? (RTM should also be a part of the deliverable for review)
    - [ ]  Is the UTP traceable to the Low Level Design?
    - [ ]  Does each function have a minimum of one test case?
    - [ ]  Is the plan for test coverage (GCOV, ATAC tools –90%) done?
    - [ ]  Are all the compiler options that are to be used for building the software verified?
Is SDP for CUT studied?
  - [ ] **Safety Checks**
    - [ ] Is Statement coverage is 100% statisfied?
    - [ ] Is Branch Coverage is 100% statisfied?

- [ ] **Unit Test Cases Review**
  - [ ] **General**
    - [ ]  Are test cases identified for all units identified in the design document?
    - [ ]  Do the test cases cover all possible combinations of inputs and outputs of every unit?
    - [ ]  Do the test cases cover all possible ranges of correct inputs and outputs?
    - [ ]  Are test cases identified to test all possible boundary conditions (including table indexes, array indexes, pointer sizes and string sizes)?
    - [ ]  Do the test cases cover all the data structures implemented in the units and/or modules?
    - [ ]  Are test cases included to test every possible operation on every MIB (Management Information Base) object?
    - [ ]  Are test cases included to test mutual exclusion, shared access etc?Are test cases included to test all
    - [ ]  initializations?
    - [ ]  Are test cases included to check initialization failures?
    - [ ]  Are test cases included to check Static Code analysis?
    - [ ]  Are test cases included to check all Requirement?
    - [ ]  Are test cases included to check all Interface?
    - [ ]  Are test cases included to test all possible performance parameters for the units?
    - [ ]  Are negative test cases included to test the software's responses to all possible error conditions - memory allocation failures, CRU buffer allocation failures, failure to enqueue a message, resource acquisition failures, failures from function calls or requests to other units?
    - [ ]  Are negative test cases included to test the software's responses to all possible erroneous inputs - data inputs, message inputs, etc?
    - [ ]  Are test cases included for failure in external module APIs?
    - [ ]  In the calling functions, are test cases included to test all possible return values from called functions?
  - [ ] **Safety Check**
    - [ ] Does the Test cases covered all requirement ?
    - [ ] Does the test case covered Boundry check analysis
    - [ ] Does the test cases coveres Generation and analysis of equivalence classes
   



 




