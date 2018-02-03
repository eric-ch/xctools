--
-- Copyright (c) 2012 Citrix Systems, Inc.
-- 
-- This library is free software; you can redistribute it and/or
-- modify it under the terms of the GNU Lesser General Public
-- License as published by the Free Software Foundation; either
-- version 2.1 of the License, or (at your option) any later version.
-- 
-- This library is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
-- Lesser General Public License for more details.
-- 
-- You should have received a copy of the GNU Lesser General Public
-- License along with this library; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
--

import Distribution.Simple
import Distribution.Simple.PreProcess
import Distribution.Simple.PreProcess.Unlit (unlit)
import Distribution.PackageDescription as PD
         ( PackageDescription(..), BuildInfo(..)
         , Executable(..)
         , Library(..), libModules
         , TestSuite(..), testModules
         , TestSuiteInterface(..)
         , Benchmark(..), benchmarkModules, BenchmarkInterface(..) )
import qualified Distribution.InstalledPackageInfo as Installed
         ( InstalledPackageInfo_(..) )
import qualified Distribution.Simple.PackageIndex as PackageIndex
import Distribution.Simple.LocalBuildInfo
         ( LocalBuildInfo(..), Component(..) )
import Distribution.Simple.BuildPaths (autogenModulesDir,cppHeaderName)
import Distribution.Simple.Program
         ( Program(..), ConfiguredProgram(..), programPath
         , requireProgram, requireProgramVersion
         , rawSystemProgramConf, rawSystemProgram
         , hsc2hsProgram
         , gccProgram )
import Distribution.System
         ( OS(..), buildOS, Arch(..), Platform(..) )
import Data.List (nub)
import System.FilePath (splitExtension, dropExtensions, (</>), (<.>),
                        takeDirectory, normalise, replaceExtension)
import Distribution.Simple.Program (simpleProgram)

-- Add a --with-hcs2hs-ld configuration option.
-- This could as well use ldProgram no?
hsc2hsLdProgram = simpleProgram "hsc2hs-ld"

my_ppHsc2hs :: BuildInfo -> LocalBuildInfo -> PreProcessor
my_ppHsc2hs bi lbi =
  PreProcessor {
    platformIndependent = False,
    runPreProcessor = mkSimplePreProcessor $ \inFile outFile verbosity -> do
      (gccProg, _) <- requireProgram verbosity gccProgram (withPrograms lbi)
      (ldProg, _) <- requireProgram verbosity hsc2hsLdProgram (withPrograms lbi)
      rawSystemProgramConf verbosity hsc2hsProgram (withPrograms lbi) $
          [ "--cc=" ++ programPath gccProg
          , "--ld=" ++ programPath ldProg ]

          -- Additional gcc options
       ++ [ "--cflag=" ++ opt | opt <- programDefaultArgs  gccProg
                                    ++ programOverrideArgs gccProg ]
       ++ [ "--lflag=" ++ opt | opt <- programDefaultArgs  gccProg
                                    ++ programOverrideArgs gccProg ]

          -- OSX frameworks:
       ++ [ what ++ "=-F" ++ opt
          | isOSX
          , opt <- nub (concatMap Installed.frameworkDirs pkgs)
          , what <- ["--cflag", "--lflag"] ]
       ++ [ "--lflag=" ++ arg
          | isOSX
          , opt <- PD.frameworks bi ++ concatMap Installed.frameworks pkgs
          , arg <- ["-framework", opt] ]

          -- Note that on ELF systems, wherever we use -L, we must also use -R
          -- because presumably that -L dir is not on the normal path for the
          -- system's dynamic linker. This is needed because hsc2hs works by
          -- compiling a C program and then running it.

       ++ [ "--cflag="   ++ opt | opt <- platformDefines lbi ]

          -- Options from the current package:
       ++ [ "--cflag=-I" ++ dir | dir <- PD.includeDirs  bi ]
       ++ [ "--cflag="   ++ opt | opt <- PD.ccOptions    bi
                                      ++ PD.cppOptions   bi ]
       ++ [ "--lflag=-L" ++ opt | opt <- PD.extraLibDirs bi ]
       ++ [ "--lflag=-Wl,-R," ++ opt | isELF
                                , opt <- PD.extraLibDirs bi ]
       ++ [ "--lflag=-l" ++ opt | opt <- PD.extraLibs    bi ]
       ++ [ "--lflag="   ++ opt | opt <- PD.ldOptions    bi ]

          -- Options from dependent packages
       ++ [ "--cflag=" ++ opt
          | pkg <- pkgs
          , opt <- [ "-I" ++ opt | opt <- Installed.includeDirs pkg ]
                ++ [         opt | opt <- Installed.ccOptions   pkg ]
                ++ [ "-I" ++ autogenModulesDir lbi,
                     "-include", autogenModulesDir lbi </> cppHeaderName ] ]
       ++ [ "--lflag=" ++ opt
          | pkg <- pkgs
          , opt <- [ "-L" ++ opt | opt <- Installed.libraryDirs    pkg ]
                ++ [ "-Wl,-R," ++ opt | isELF
                                 , opt <- Installed.libraryDirs    pkg ]
                ++ [ "-l" ++ opt | opt <- Installed.extraLibraries pkg ]
                ++ [         opt | opt <- Installed.ldOptions      pkg ] ]
       ++ ["-o", outFile, inFile]
  }
  where
    pkgs = PackageIndex.topologicalOrder (packageHacks (installedPkgs lbi))
    isOSX = case buildOS of OSX -> True; _ -> False
    isELF = case buildOS of OSX -> False; Windows -> False; _ -> True;
    packageHacks = case compilerFlavor (compiler lbi) of
      GHC -> hackRtsPackage
      _   -> id
    -- We don't link in the actual Haskell libraries of our dependencies, so
    -- the -u flags in the ldOptions of the rts package mean linking fails on
    -- OS X (it's ld is a tad stricter than gnu ld). Thus we remove the
    -- ldOptions for GHC's rts package:
    hackRtsPackage index =
      case PackageIndex.lookupPackageName index (PackageName "rts") of
        [(_, [rts])]
           -> PackageIndex.insert rts { Installed.ldOptions = [] } index
        _  -> error "No (or multiple) ghc rts package is registered!!"

main = defaultMainWithHooks $ simpleUserHooks {
         hookedPreProcessors = [ ("hsc", my_ppHsc2hs) ]
       , hookedPrograms = hsc2hsLdProgram : hookedPrograms simpleUserHooks
       }
