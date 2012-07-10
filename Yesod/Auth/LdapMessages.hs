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
                 | EmailNotRegistered
                 | Username
                 | OldPassword
                 | WrongOldPassword
                 | ChangePassword
                 | ForgetPassword
                 | ConfirmationEmailSent Text
                 | ConfirmationEmailSentSpam
                 | Send
                 | EnterEmailLong
                 | LoginError LDAPAuthResult
                 | ForgetLong
                 | RegistrationError LDAPRegResult Text
                 | ValidationPassMismatch
                 | ValidationNotAEmail
                 | PasswordUpdateError LDAPPassUpdateResult


defaultMessage :: LdapMessage -> Text
defaultMessage = englishMessage

englishMessage :: LdapMessage -> Text
englishMessage EmailAlreadyRegistered = "This e-mail address is already registered."
englishMessage EmailNotRegistered = "This e-mail is not registered"
englishMessage Username = "Username"
englishMessage OldPassword = "Old Password"
englishMessage WrongOldPassword = "The old Password is wrong."
englishMessage ChangePassword = "Change Password"
englishMessage ForgetPassword = "Forget Password"
englishMessage Send           = "Send"
englishMessage ForgetLong     = "If you've forgotten your password, you can enter your e-mail address, an we will send you an activation link, so you can set an new password"
englishMessage (PasswordUpdateError (UnexpectedPassUpdateError e)) = "An unexpected error occured. Please try again or send us a e-mail" `mappend` (pack $ show e)
englishMessage (PasswordUpdateError _) = undefined  -- TDOD rethink errorhandling
englishMessage (LoginError InitialBindFail) = "Unexpected error during login."
englishMessage (LoginError _) = "User not found or wrong password."
englishMessage EnterEmailLong = "Enter your e-mail address to star the registration."
englishMessage ConfirmationEmailSentSpam = "Please check your spam folder."
englishMessage (ConfirmationEmailSent email) = 
    "A confirmation e-mail has been sent to " `mappend`
    email `mappend`
    "."



germanMessage :: LdapMessage -> Text
germanMessage EmailAlreadyRegistered = "Diese E-Mail Adresse ist bereits registriert."
germanMessage EmailNotRegistered  = "Diese E-Mail Adresse ist bei uns nicht registriert"
germanMessage Username = "Benutzername"
germanMessage OldPassword = "Altes Passwort"
germanMessage WrongOldPassword = "Das alte Passwort ist falsch."
germanMessage ChangePassword = "Passwort ändern"
germanMessage ForgetPassword = "Passwort vergessen"
germanMessage Send           = "Abschicken"
germanMessage ForgetLong     = "Wenn du dein Passwort vergessen hast, trage deine E-Mail ein. Du erhältst dann eine E-Mail mit einem Link. Klicke ihn an, um ein neues Passwort zu wählen."
germanMessage (RegistrationError UsernameUsed username) = "Der Benutzername " `mappend` username `mappend` " ist schon in Benutzung."
germanMessage (RegistrationError e text) = 
    "Ein unbekannter Fehler ist aufgetreten: " `mappend` 
    (pack $ show e) `mappend` 
    " : " `mappend` text

germanMessage (PasswordUpdateError (UnexpectedPassUpdateError e)) = "Es ist ein unerwarteter Fehler aufgetreten, bitte versuche es noch einmal oder schreibe uns: " `mappend` (pack $ show e)
germanMessage (PasswordUpdateError _) = undefined -- TDOD rethink errorhandling
germanMessage (LoginError InitialBindFail) = "Unerwarteter Fehler aufgetreten."
germanMessage (LoginError _) = "Falsches Passwort oder Benutzer nicht gefunden."
germanMessage EnterEmailLong = "Um dich zu registrieren, gib bitte zunächst deine E-Mail Adresse ein. Du erhältst dann eine E-Mail mit einem Link. Klicke ihn an, um zu bestätigen, dass die Adresse dir gehört. Danach kannst du einen Benutzernamen und ein Passwort wählen."
germanMessage ConfirmationEmailSentSpam = "Solltest du scheinbar keine E-Mail erhalten haben, prüfe bitte deinen Spam-Ordner."
germanMessage (ConfirmationEmailSent email) = 
    "Eine Bestätigung wurde an " `mappend`
    email `mappend`
    " versandt."