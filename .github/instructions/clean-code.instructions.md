---
description: "Clean Code principles and best practices for writing maintainable, readable, and high-quality code"
applyTo: "**"
---

# Clean Code Principles

## Core Philosophy

Write code for humans first, computers second. Code is read far more often than it is written, so optimize for readability and maintainability.

## Meaningful Names

### Variables and Parameters

- **Reveal Intent**: Names should answer why it exists, what it does, and how it's used

  ```csharp
  // Bad
  int d; // elapsed time in days

  // Good
  int elapsedTimeInDays;
  ```

- **Avoid Disinformation**: Don't use names that vary in small ways

  ```csharp
  // Bad
  var accountList = new Dictionary<int, Account>(); // It's not a list!

  // Good
  var accountsByNumber = new Dictionary<int, Account>();
  ```

- **Make Meaningful Distinctions**: Don't add noise words

  ```csharp
  // Bad
  void CopyChars(char[] a1, char[] a2);

  // Good
  void CopyChars(char[] source, char[] destination);
  ```

- **Use Pronounceable Names**: If you can't pronounce it, you can't discuss it

  ```csharp
  // Bad
  DateTime genymdhms; // generation year, month, day, hour, minute, second

  // Good
  DateTime generationTimestamp;
  ```

### Functions and Methods

- **Verbs for Actions**: Use verb phrases for methods that do something

  ```csharp
  // Good
  void SaveCustomer();
  bool IsValidEmail(string email);
  string FormatCurrency(decimal amount);
  ```

- **One Word Per Concept**: Be consistent across the codebase

  ```csharp
  // Bad: mixing fetch, retrieve, get
  Customer FetchCustomer();
  Order RetrieveOrder();
  Product GetProduct();

  // Good: consistent verb usage
  Customer GetCustomer();
  Order GetOrder();
  Product GetProduct();
  ```

### Classes

- **Noun or Noun Phrases**: Classes represent things

  ```csharp
  // Good
  class Customer { }
  class EmailValidator { }
  class OrderProcessor { }
  ```

- **Avoid Generic Names**: Manager, Processor, Data, Info are too vague (use sparingly)

## Functions

### Small Functions

- **Do One Thing**: Functions should do one thing, do it well, and do it only
- **One Level of Abstraction**: All statements in a function should be at the same level of abstraction
- **Keep Them Short**: Ideally 5-10 lines, rarely more than 20

### Function Arguments

- **Minimize Arguments**: Zero is ideal, one is good, two is okay, three should be avoided, more than three requires special justification

  ```csharp
  // Bad: too many arguments
  void CreateAccount(string firstName, string lastName, string email, string phone, string address, string city, string state, string zip);

  // Good: use objects to group related data
  void CreateAccount(PersonalInfo info, ContactInfo contact, Address address);
  ```

- **Avoid Flag Arguments**: They indicate the function does more than one thing

  ```csharp
  // Bad
  void SaveCustomer(Customer customer, bool validate);

  // Good: split into two functions
  void SaveCustomer(Customer customer);
  void SaveCustomerWithoutValidation(Customer customer);
  ```

### Side Effects

- **Avoid Hidden Side Effects**: Functions should do what their name says, nothing more
- **Command Query Separation**: Functions should either do something or answer something, not both

## Comments

### When to Comment

- **Explain WHY, not WHAT**: Code should explain what it does; comments explain why

  ```csharp
  // Bad: stating the obvious
  // Increment counter by one
  counter++;

  // Good: explaining business logic
  // Apply progressive tax brackets: 10% up to 10k, 20% above
  var tax = CalculateProgressiveTax(income, [0.10, 0.20], [10000]);
  ```

- **Legal Comments**: Copyright and authorship information
- **Warnings of Consequences**: Alert other developers about specific consequences
- **TODO Comments**: Leave notes for future improvements (but don't let them accumulate)

### When NOT to Comment

- **Redundant Comments**: Comments that say the same thing as the code
- **Misleading Comments**: Comments that are inaccurate or outdated
- **Noise Comments**: Comments that add no information
- **Commented-Out Code**: Delete it; version control has your back
- **HTML in Comments**: Makes comments hard to read

### Comment Alternatives

- **Better Names**: Instead of commenting a variable, rename it
- **Extract to Function**: Instead of commenting a block, extract it to a well-named function
- **Use Constants**: Replace magic numbers with named constants

## Code Structure

### Vertical Formatting

- **Small Files**: Files should be small (200-500 lines max)
- **Newspaper Metaphor**: High-level concepts at top, details at bottom
- **Vertical Openness**: Separate concepts with blank lines
- **Vertical Density**: Group tightly related code together

### Horizontal Formatting

- **Short Lines**: Keep lines under 120 characters
- **Use Whitespace**: Use horizontal whitespace to associate strongly related things and disassociate weakly related things

### Class Organization

- **Top to Bottom**:
  1. Constants
  2. Fields
  3. Constructors
  4. Public methods
  5. Private methods (called by public methods above them)

## Error Handling

### Use Exceptions, Not Error Codes

- **Don't Return Null**: Return empty collections or use Option/Maybe pattern

  ```csharp
  // Bad
  List<Customer> GetCustomers()
  {
      if (noCustomers) return null; // Caller must check for null
  }

  // Good
  List<Customer> GetCustomers()
  {
      return customers ?? new List<Customer>(); // Return empty list
  }
  ```

- **Don't Pass Null**: Avoid passing null as arguments
- **Extract Try/Catch Blocks**: Error handling is one thing; extract it

  ```csharp
  // Good
  public void Delete(Customer customer)
  {
      try
      {
          DeleteCustomer(customer);
      }
      catch (Exception ex)
      {
          LogError(ex);
          throw;
      }
  }

  private void DeleteCustomer(Customer customer)
  {
      // Actual deletion logic
  }
  ```

## SOLID Principles (Brief Reminders)

### Single Responsibility Principle (SRP)

- A class should have only one reason to change
- Each class/function should do one thing well

### Open/Closed Principle (OCP)

- Open for extension, closed for modification
- Use interfaces and abstractions to allow new behavior without changing existing code

### Liskov Substitution Principle (LSP)

- Subtypes must be substitutable for their base types
- Derived classes should extend, not replace, base class behavior

### Interface Segregation Principle (ISP)

- Many specific interfaces are better than one general-purpose interface
- Clients shouldn't depend on methods they don't use

### Dependency Inversion Principle (DIP)

- Depend on abstractions, not concretions
- High-level modules should not depend on low-level modules

## Code Smells to Avoid

### Common Smells

- **Duplicated Code**: Extract to a method or class
- **Long Methods**: Break into smaller, focused methods
- **Large Classes**: Split responsibilities into multiple classes
- **Long Parameter Lists**: Use objects to group parameters
- **Divergent Change**: One class changes for multiple reasons (violates SRP)
- **Shotgun Surgery**: One change requires many small changes in many classes
- **Feature Envy**: Method is more interested in another class than its own
- **Data Clumps**: Groups of data that always appear together (should be a class)
- **Primitive Obsession**: Using primitives instead of small objects for simple tasks
- **Switch Statements**: Consider polymorphism instead
- **Speculative Generality**: "We might need this someday" (YAGNI - You Aren't Gonna Need It)

### Refactoring Techniques

- **Extract Method**: Turn code fragment into a method
- **Extract Class**: Create a new class for related functionality
- **Inline Method/Class**: Remove unnecessary indirection
- **Rename**: Make names more meaningful
- **Move Method/Field**: Move to a more appropriate class
- **Replace Magic Number with Constant**: Use named constants

## Testing and Clean Code

### Test Code is Production Code

- Tests should be clean, readable, and maintainable
- Follow the same standards as production code
- Use descriptive test names: `MethodName_Condition_ExpectedResult()`

### F.I.R.S.T. Principles

- **Fast**: Tests should run quickly
- **Independent**: Tests should not depend on each other
- **Repeatable**: Tests should produce same results every time
- **Self-Validating**: Tests should have boolean output (pass/fail)
- **Timely**: Write tests before or with production code (TDD)

## Boy Scout Rule

**Leave the code cleaner than you found it.**

Even small improvements compound over time. If everyone leaves the code a little better than they found it, the codebase continually improves.

## Summary Checklist

- [ ] Names are meaningful and reveal intent
- [ ] Functions are small and do one thing
- [ ] Code is self-documenting; comments explain WHY, not WHAT
- [ ] No duplicated code (DRY - Don't Repeat Yourself)
- [ ] Error handling is separated from business logic
- [ ] Tests are clean and follow F.I.R.S.T. principles
- [ ] SOLID principles are followed
- [ ] Code smells are addressed through refactoring
- [ ] Code is easier to read and understand after your changes
