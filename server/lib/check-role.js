/* 
Checks role mapping from oauth JWT token
Looks inside an array for role mapping matching configuration
============================================================================= */

/**
 * Evaluate role from configuration and list
 * @returns {string}
 */
module.exports = function getRoleFromOAuth(roles, prefix) {  
  if (roles) {
    if(roles.includes(prefix + ':admin')) {
      return 'admin'
    } else if(roles.includes(prefix + ':editor')) {
      return 'editor'
    }
  }
  return ''
}
