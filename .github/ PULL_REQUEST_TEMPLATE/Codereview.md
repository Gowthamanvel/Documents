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
