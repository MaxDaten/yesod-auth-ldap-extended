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
                 | OldPassword
                 | ChangePassword
                 | ForgetPassword
                 | Send
                 | RegistrationError LDAPRegResult Text
                 | PasswordUpdateError LDAPPassUpdateResult


defaultMessage :: LdapMessage -> Text
defaultMessage = englishMessage

englishMessage :: LdapMessage -> Text
englishMessage EmailAlreadyRegistered = "This e-mail address is already registered."
englishMessage Username = "Username"
englishMessage OldPassword = "Old Password"
englishMessage ChangePassword = "Change Password"
englishMessage ForgetPassword = "Forget Password"
englishMessage Send           = "Send"
englishMessage (PasswordUpdateError (UnexpectedPassUpdateError e)) = "An unexpected error occured. Please try again or send us a e-mail" `mappend` (pack $ show e)



germanMessage :: LdapMessage -> Text
germanMessage EmailAlreadyRegistered = "Diese E-Mail Adresse ist bereits registriert."
germanMessage Username = "Benutzername"
germanMessage OldPassword = "Altes Passwort"
germanMessage ChangePassword = "Passwort ändern"
germanMessage ForgetPassword = "Passwort vergessen"
germanMessage Send           = "Abschicken"
germanMessage (RegistrationError UsernameUsed username) = "Der Benutzername " `mappend` username `mappend` " ist schon in Benutzung."
germanMessage (RegistrationError e text) = 
    "Ein unbekannter Fehler ist aufgetreten: " `mappend` 
    (pack $ show e) `mappend` 
    " : " `mappend` text

germanMessage (PasswordUpdateError (UnexpectedPassUpdateError e)) = "Es ist ein unerwarteter Fehler aufgetreten, bitte versuche es noch einmal oder schreibe uns: " `mappend` (pack $ show e)