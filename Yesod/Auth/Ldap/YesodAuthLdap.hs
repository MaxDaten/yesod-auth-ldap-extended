{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Yesod.Auth.Ldap.YesodAuthLdap
    ( YesodAuthLdap (..)
    , Email
    , VerKey
    , VerUrl
    , Pass
    ) where


import Yesod.Auth
import Yesod.Message (RenderMessage (..))


import Yesod.Form
import Yesod.Handler

import Data.Text (Text)

import Web.Authenticate.LDAP 
    ( LdapAuthConfig
    , LdapBindConfig
    , LDAPRegResult
    , LDAPPassUpdateResult
    )
import Yesod.Auth.LdapMessages (LdapMessage)
import qualified Yesod.Auth.LdapMessages as LdapM
import Yesod.Auth.Message (AuthMessage)

type Email  = Text
type VerKey = Text
type VerUrl = Text
type Pass   = Text

class (YesodAuth m, RenderMessage m FormMessage) => YesodAuthLdap m where
    --type AuthLdapId m
    sendVerifyEmail :: Email -> VerKey -> VerUrl -> GHandler Auth m ()
    sendForgetEmail :: Email -> VerKey -> VerUrl -> GHandler Auth m ()
    register        :: Email -> Pass -> AuthId m -> LdapAuthConfig -> LdapBindConfig -> GHandler Auth m (LDAPRegResult)
    updatePassword  :: AuthId m -> Pass -> LdapAuthConfig -> LdapBindConfig -> GHandler Auth m (LDAPPassUpdateResult)
    login :: AuthId m -> Pass -> LdapAuthConfig -> LdapBindConfig -> GHandler Auth m (Bool)
    
    renderLdapMessage :: m -> [Text] -> LdapMessage -> Text
    renderLdapMessage _ _ = LdapM.defaultMessage

    
instance YesodAuthLdap m => RenderMessage m LdapMessage where
    renderMessage = renderLdapMessage