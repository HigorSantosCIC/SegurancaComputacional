
//  (C) Copyright Edward Diener 2011,2012,2013
//  Use, modification and distribution are subject to the Boost Software License,
//  Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt).

#if !defined(BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION_HPP)
#define BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION_HPP

#include <boost/config.hpp>
#include <boost/function_types/property_tags.hpp>
#include <boost/mpl/vector.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/tti/detail/dstatic_mem_fun.hpp>
#include <boost/tti/gen/has_static_member_function_gen.hpp>

/*

  The succeeding comments in this file are in doxygen format.

*/

/** \file
*/

/// A macro which expands to a metafunction which tests whether a static member function with a particular name and signature exists.
/**

    BOOST_TTI_TRAIT_HAS_STATIC_MEMBER_FUNCTION is a macro which expands to a metafunction.
    The metafunction tests whether a static member function with a particular name
    and signature exists. The macro takes the form of BOOST_TTI_TRAIT_HAS_STATIC_MEMBER_FUNCTION(trait,name) where
    
    trait = the name of the metafunction <br/>
    name  = the name of the inner member.

    BOOST_TTI_TRAIT_HAS_STATIC_MEMBER_FUNCTION generates a metafunction called "trait" where 'trait' is the macro parameter.
    
  @code
  
              template<class BOOST_TTI_TP_T,class BOOST_TTI_TP_R,class BOOST_TTI_TP_FS,class BOOST_TTI_TP_TAG>
              struct trait
                {
                static const value = unspecified;
                typedef mpl::bool_<true-or-false> type;
                };

              The metafunction types and return:
    
                BOOST_TTI_TP_T   = the enclosing type in which to look for our 'name'.
                                   The enclosing type can be a class, struct, or union.
                
                BOOST_TTI_TP_R   = the return type of the static member function
                                       OR
                          the signature of a function in the form of Return_Type ( Parameter_Types )
                
                BOOST_TTI_TP_FS  = (optional) the parameters of the static member function as a boost::mpl forward sequence
                          if the second parameter is a return type and the function parameters exist.
                
                BOOST_TTI_TP_TAG = (optional) a boost::function_types tag to apply to the static member function
                          if the second parameter is a return type and the need for a tag exists.
                
                returns = 'value' is true if the 'name' exists, 
                          with the appropriate static member function type,
                          otherwise 'value' is false.
                          
  @endcode
  
*/
#define BOOST_TTI_TRAIT_HAS_STATIC_MEMBER_FUNCTION(trait,name) \
  BOOST_TTI_DETAIL_TRAIT_HAS_STATIC_MEMBER_FUNCTION(trait,name) \
  template<class BOOST_TTI_TP_T,class BOOST_TTI_TP_R,class BOOST_TTI_TP_FS = boost::mpl::vector<>,class BOOST_TTI_TP_TAG = boost::function_types::null_tag> \
  struct trait \
    { \
    typedef typename \
    BOOST_PP_CAT(trait,_detail_hsmf)<BOOST_TTI_TP_T,BOOST_TTI_TP_R,BOOST_TTI_TP_FS,BOOST_TTI_TP_TAG>::type type; \
    BOOST_STATIC_CONSTANT(bool,value=type::value); \
    }; \
/**/

/// A macro which expands to a metafunction which tests whether a static member function with a particular name and signature exists.
/**

    BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION is a macro which expands to a metafunction.
    The metafunction tests whether a static member function with a particular name
    and signature exists. The macro takes the form of BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION(name) where
    
    name  = the name of the inner member.

    BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION generates a metafunction called "has_static_member_function_name" where 'name' is the macro parameter.
    
  @code
  
              template<class BOOST_TTI_TP_T,class BOOST_TTI_TP_R,class BOOST_TTI_TP_FS,class BOOST_TTI_TP_TAG>
              struct has_static_member_function_'name'
                {
                static const value = unspecified;
                typedef mpl::bool_<true-or-false> type;
                };

              The metafunction types and return:
    
                BOOST_TTI_TP_T   = the enclosing type in which to look for our 'name'.
                                   The enclosing type can be a class, struct, or union.
                
                BOOST_TTI_TP_R   = the return type of the static member function
                                       OR
                          the signature of a function in the form of Return_Type ( Parameter_Types )
                
                BOOST_TTI_TP_FS  = (optional) the parameters of the static member function as a boost::mpl forward sequence
                          if the second parameter is a return type and the function parameters exist.
                
                BOOST_TTI_TP_TAG = (optional) a boost::function_types tag to apply to the static member function
                          if the second parameter is a return type and the need for a tag exists.
                
                returns = 'value' is true if the 'name' exists, 
                          with the appropriate static member function type,
                          otherwise 'value' is false.
                          
  @endcode
  
*/
#define BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION(name) \
  BOOST_TTI_TRAIT_HAS_STATIC_MEMBER_FUNCTION \
  ( \
  BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION_GEN(name), \
  name \
  ) \
/**/

#endif // BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION_HPP
