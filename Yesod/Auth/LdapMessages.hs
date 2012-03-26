{-# LANGUAGE OverloadedStrings #-}
module Yesod.Auth.LdapMessages
    ( LdapMessage (..)
    , defaultMessage
    , germanMessage
    ) where

import Data.Monoid (mappend)
import Data.Text (Text, pack)
import Web.Authenticate.LDAP

data LdapMessage = EmailAlreadyRegistered
                 | Username
                 | RegistrationError LDAPRegResult Text


defaultMessage :: LdapMessage -> Text
defaultMessage = englishMessage

englishMessage :: LdapMessage -> Text
englishMessage EmailAlreadyRegistered = "This e-mail address is already registered."
englishMessage Username = "Username"

germanMessage :: LdapMessage -> Text
germanMessage EmailAlreadyRegistered = "Diese E-Mail Adresse ist bereits registriert."
germanMessage Username = "Benutzername"

germanMessage (RegistrationError UsernameUsed username) = "Der Benutzername " `mappend` username `mappend` " ist schon in Benutzung."
germanMessage (RegistrationError e text) = 
    "Ein unbekannter Fehler ist aufgetreten: " `mappend` 
    (pack $ show e) `mappend` 
    " : " `mappend` text
