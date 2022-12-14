<!--- DO NOT EDIT: This file is automatically generated by markdown plugin

package main

import (
)
--->
# Table of Contents

* [Types](#types)
* [Queries](#queries)
* [Mutations](#mutations)

# Types

* [ApplicationCompany](#applicationcompany)


* [ApplicationCustomData](#applicationcustomdata)


* [ApplicationCustomSource](#applicationcustomsource)


* [ApplicationUser](#applicationuser)


* [ApplicationUserLanguage](#applicationuserlanguage)

### ApplicationCompany

> This object represents a single Application Company.

Name | Type | Description
-|-|-
companyID | ID | primary key generated by the server
companyName | String | name of company
createDate | Int | epoch millis timestamp

### Related Queries

* [ListApplicationCompany](#listapplicationcompany)


### Related Mutations


---


### ApplicationCustomData

> This object represents fields of custom data type.

Name | Type | Description
-|-|-
foo | String | 
bar | String | 

### Related Queries



### Related Mutations


---

### ApplicationCustomSource

> This object represents fields from custom data source.

Name | Type | Description
-|-|-
custom | ApplicationCustomData | 

### Related Queries



### Related Mutations


---

### ApplicationUser

> This object represents a single Application User.

Name | Type | Description
-|-|-
userID | ID | primary key generated by the server
userName | String | name of user
companyID | String | companyID used to link a user to a company
company | ApplicationCompany | 
createDate | Int | epoch millis timestamp
languages | ApplicationUserLanguage | return list of languages user speaks
customData | ApplicationCustomSource | return opjects from custom source

### Related Queries

* [GetApplicationUser](#getapplicationuser)
* [SearchApplicationUser](#searchapplicationuser)


### Related Mutations

* [CreateApplicationUser](#createapplicationuser)
* [UpdateApplicationUser](#updateapplicationuser)

---

### ApplicationUserLanguage

> This object represents languages user's have command of.

Name | Type | Description
-|-|-
userID | ID | primary key generated by the server
userLanguage | String | language

### Related Queries



### Related Mutations

* [CreateApplicationUserLanguage](#createapplicationuserlanguage)
* [DeleteApplicationUserLanguage](#deleteapplicationuserlanguage)

---



























# Queries



* [getApplicationUser](#getapplicationuser)


* [searchApplicationUser](#searchapplicationuser)


* [listApplicationCompany](#listapplicationcompany)


## getApplicationUser

> Return a Application User object from userID.

### Roles Allowed



### Arguments

Name | Type | Required | Key | Description | Example Value
-|-|-|-|-|-
userID |String! | true|hash key| userID is the unique identifier for the user |`00000000-0000-0000-0000-000000000000`

### Output Type

* [ApplicationUser](#applicationuser)


### Example Query

```graphql
query {
  getApplicationUser(
      userID: "00000000-0000-0000-0000-000000000000"
  ) {
    items {
      userID
      userName
      companyID
      company {
        companyID
        companyName
        createDate
      }
      createDate
      languages {
        userID
        userLanguage
      }
      customData {
        custom {
          foo
          bar
        }
      }
    }
  }
}
```
## searchApplicationUser

> Return a Application User object by userName.

### Roles Allowed



### Arguments

Name | Type | Required | Key | Description | Example Value
-|-|-|-|-|-
userName |String! | true|hash key| userName of the user |`craftycoder`

### Output Type

* [ApplicationUser](#applicationuser)


### Example Query

```graphql
query {
  searchApplicationUser(
      userName: "craftycoder"
  ) {
    items {
      userID
      userName
      companyID
      company {
        companyID
        companyName
        createDate
      }
      createDate
      languages {
        userID
        userLanguage
      }
      customData {
        custom {
          foo
          bar
        }
      }
    }
  }
}
```
## listApplicationCompany

> Return a list of all Application Company objects.

### Roles Allowed



### Output Type

* [ApplicationCompany](#applicationcompany)


### Example Query

```graphql
query {
  listApplicationCompany(
  ) {
    items {
      companyID
      companyName
      createDate
    }
  }
}
```


# Mutations



* [createApplicationUser](#createapplicationuser)


* [updateApplicationUser](#updateapplicationuser)


* [createApplicationUserLanguage](#createapplicationuserlanguage)


* [deleteApplicationUserLanguage](#deleteapplicationuserlanguage)


## createApplicationUser

> Creates a new Application User object.

### Roles Allowed



### Mutations Allowed

Insert | Update | Delete
-|-|-
true |false |false

### Arguments

Name | Type | Required | Key | Description | Example Value
-|-|-|-|-|-
userName |String! | true|| name of user |`testuser6`
companyID |String! | true|| companyId of the user |`10101010-0000-0000-0000-000000000000`

### Output Type

* [ApplicationUser](#applicationuser)


### Example Mutation

```graphql
mutation {
  createApplicationUser(
      userName: "testuser6"
      companyID: "10101010-0000-0000-0000-000000000000"
  ) {
    items {
      userID
      userName
      companyID
      company {
        companyID
        companyName
        createDate
      }
      createDate
      languages {
        userID
        userLanguage
      }
      customData {
        custom {
          foo
          bar
        }
      }
    }
  }
}
```
## updateApplicationUser

> Update an Application User object.

### Roles Allowed



### Mutations Allowed

Insert | Update | Delete
-|-|-
false |true |false

### Arguments

Name | Type | Required | Key | Description | Example Value
-|-|-|-|-|-
userID |String! | true|hash key| userID is the unique identifier for the user |`00000000-0000-0000-0000-000000000000`
userName |String! | true|range key| name of user |`craftycoder`
companyID |String! | true|| companyId of the user |`10101010-0000-0000-0000-000000000000`

### Output Type

* [ApplicationUser](#applicationuser)


### Example Mutation

```graphql
mutation {
  updateApplicationUser(
      userID: "00000000-0000-0000-0000-000000000000"
      userName: "craftycoder"
      companyID: "10101010-0000-0000-0000-000000000000"
  ) {
    items {
      userID
      userName
      companyID
      company {
        companyID
        companyName
        createDate
      }
      createDate
      languages {
        userID
        userLanguage
      }
      customData {
        custom {
          foo
          bar
        }
      }
    }
  }
}
```
## createApplicationUserLanguage

> Creates a new Application User Language object.

### Roles Allowed



### Mutations Allowed

Insert | Update | Delete
-|-|-
true |false |false

### Arguments

Name | Type | Required | Key | Description | Example Value
-|-|-|-|-|-
userID |String! | true|hash key| userID is the unique identifier for the user |`00000000-0000-0000-0000-000000000000`
userLanguage |String! | true|range key| language |`english`

### Output Type

* [ApplicationUserLanguage](#applicationuserlanguage)


### Example Mutation

```graphql
mutation {
  createApplicationUserLanguage(
      userID: "00000000-0000-0000-0000-000000000000"
      userLanguage: "english"
  ) {
    items {
      userID
      userLanguage
    }
  }
}
```
## deleteApplicationUserLanguage

> Delete an Application User Language object.

### Roles Allowed



### Mutations Allowed

Insert | Update | Delete
-|-|-
false |false |true

### Arguments

Name | Type | Required | Key | Description | Example Value
-|-|-|-|-|-
userID |String! | true|hash key| userID is the unique identifier for the user |`00000000-0000-0000-0000-000000000000`
userLanguage |String! | true|range key| language |`english`

### Output Type

* [ApplicationUserLanguage](#applicationuserlanguage)


### Example Mutation

```graphql
mutation {
  deleteApplicationUserLanguage(
      userID: "00000000-0000-0000-0000-000000000000"
      userLanguage: "english"
  ) {
    items {
      userID
      userLanguage
    }
  }
}
```
