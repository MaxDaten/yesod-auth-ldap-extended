{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Yesod.Auth.Ldap.Handler.Password 
    ( SetPasswordState(..)
    -- * routes
    , setpassR
    , resetpassR
    , changepassR
    -- * posts/gets
    , getPasswordR
    , postPasswordR
    ) where

import Yesod.Auth
import Control.Applicative
import Data.Text (Text)

import Yesod.Message (RenderMessage (..))
import qualified Yesod.Auth.Message as Msg
import qualified Yesod.Auth.LdapMessages as LdapM
import Yesod.Auth.LdapMessages (LdapMessage, defaultMessage)

import Control.Monad (when)  
import Control.Monad.IO.Class (liftIO)

import Yesod.Form
import Yesod.Handler
import Yesod.Content
import Yesod.Core (PathPiece, fromPathPiece, whamlet, defaultLayout, setTitleI, toPathPiece)

import Web.Authenticate.LDAP
import LDAP

import Yesod.Auth.Ldap.YesodAuthLdap

setpassR, changepassR, resetpassR:: AuthRoute

setpassR    = PluginR "ldap" ["set-password"]
resetpassR  = PluginR "ldap" ["reset-password"]
changepassR = PluginR "ldap" ["change-password"]


data SetPasswordState = NewUser
                      | ResetPassword
                      | ChangePassword


getPasswordR :: YesodAuthLdap master 
             => SetPasswordState
             -> GHandler Auth master RepHtml
getPasswordR state = do    
    toMaster <- getRouteToMaster
    maid <- maybeAuthId
    case maid of
        Just _ -> return ()
        Nothing -> do
            setMessageI Msg.BadSetPass
            redirect $ toMaster LoginR
    defaultLayout $ do
        setTitleI Msg.SetPassTitle
        [whamlet|
$case state
    $of NewUser
        <h3>_{Msg.Register}
        <form method="post" action="@{toMaster setpassR}">
            <table>
                <tr>
                    <th>_{LdapM.Username}
                    <td>
                        <input type="text" name="username" required>
                <tr>
                    <th>_{Msg.NewPass}
                    <td>
                            <input type="password" name="new" required>
                <tr>
                    <th>_{Msg.ConfirmPass}
                    <td>
                        <input type="password" name="confirm" required>
                <tr>
                    <td colspan="2">
                            <input type="submit" value=_{Msg.Register}>
    $of ChangePassword
        <h3>_{LdapM.ChangePassword}
        <form method="post" action="@{toMaster changepassR}">
            <table>
                <tr>
                    <th>_{LdapM.OldPassword}
                    <td>
                        <input type="password" name="old" required>
                <tr>
                    <th>_{Msg.NewPass}
                    <td>
                            <input type="password" name="new" required>
                <tr>
                    <th>_{Msg.ConfirmPass}
                    <td>
                        <input type="password" name="confirm" required>
                <tr>
                    <td colspan="2">
                            <input type="submit" value=_{Msg.ConfirmPass}>
    $of ResetPassword
        <h3>_{LdapM.ChangePassword}
        <form method="post" action="@{toMaster resetpassR}">
            <table>
                <tr>
                    <th>_{Msg.NewPass}
                    <td>
                            <input type="password" name="new" required>
                <tr>
                    <th>_{Msg.ConfirmPass}
                    <td>
                        <input type="password" name="confirm" required>
                <tr>
                    <td colspan="2">
                            <input type="submit" value=_{Msg.ConfirmPass}>
|]



postPasswordR :: YesodAuthLdap master 
              => SetPasswordState
              -> LdapAuthConfig 
              -> LdapBindConfig 
              -> GHandler Auth master ()
postPasswordR regstate auth bind = do
    
    toMaster <- getRouteToMaster
    y <- getYesod
    
    maid <- maybeAuthId
    aid <- case maid of
            Nothing -> do
                setMessageI Msg.BadSetPass
                redirect $ toMaster LoginR
            Just aid -> return aid
    
    case regstate of
        NewUser -> do
            (username, new, confirm ) <- runInputPost $ (,,)
                <$> ireq textField "username"
                <*> ireq textField "new"
                <*> ireq textField "confirm"
                
            when (new /= confirm) $ do
                setMessageI Msg.PassMismatch
                redirect $ toMaster setpassR
            
            res <- register username new aid auth bind
            case res of
                RegOk        -> return ()
                UsernameUsed -> do
                                setMessageI $ LdapM.RegistrationError UsernameUsed username
                                redirect $ toMaster setpassR                    
                e            -> do
                                setMessageI $ LdapM.RegistrationError e username
                                redirect $ toMaster LoginR
                            
            
        ChangePassword -> do
            (old, new, confirm ) <- runInputPost $ (,,)
                <$> ireq textField "old"
                <*> ireq textField "new"
                <*> ireq textField "confirm"
                
            when (new /= confirm) $ do
                setMessageI Msg.PassMismatch
                redirect $ toMaster changepassR
            
            -- TODO check old password
            ok <- login aid old auth bind
            
            when (not ok)  $ do
                setMessageI LdapM.WrongOldPassword
                redirect $ toMaster changepassR
                
            res <- updatePassword aid new auth bind
            
            case res of
                 PassUpdateOk -> return ()
                 e -> do
                     setMessageI $ LdapM.PasswordUpdateError e
                     redirect $ loginDest y -- TODO: where to go
        ResetPassword -> do
            (new, confirm) <- runInputPost $ (,)
                <$> ireq textField "new"
                <*> ireq textField "confirm"
                
            when (new /= confirm) $ do
                setMessageI Msg.PassMismatch
                redirect $ toMaster resetpassR
            
            res <- updatePassword aid new auth bind
            case res of
                 PassUpdateOk -> return ()
                 e -> do
                     setMessageI $ LdapM.PasswordUpdateError e
                     redirect $ loginDest y -- TODO where to go?
            

    setMessageI Msg.PassUpdated
    redirect $ loginDest y
    
    

passwordConfirmField :: Field sub master Text
passwordConfirmField = Field
    { fieldParse = \rawVals ->
        case rawVals of
            [a, b]
                | a == b -> return $ Right $ Just a
                | otherwise -> return $ Left "Passwords don't match"
            [] -> return $ Right Nothing
            _ -> return $ Left "You must enter two values"
    , fieldView = \idAttr nameAttr _ eResult isReq -> [whamlet|
<input id=#{idAttr} name=#{nameAttr} type=password>
<div>Confirm:
<input id=#{idAttr}-confirm name=#{nameAttr} type=password>
|]
    }