
package tools.pki.gbay.util.general;

// ----------------------------------------------------------------------------
/**
 * Information context for {@link IClassLoadStrategy#getClassLoader(ClassLoadContext)}. 
 */
public
class ClassLoadContext
{
    // public: ................................................................
    
    /**
     * Returns the class representing the caller of {@link ClassLoaderResolver}
     * API. Can be used to retrieve the caller's classloader etc (which may be
     * different from the ClassLoaderResolver's own classloader). 
     */
    public final Class getCallerClass ()
    {
        return m_caller;
    }
    
    // protected: .............................................................

    // package: ...............................................................
    
    /**
     * This constructor is package-private to restrict instantiation to
     * {@link ClassLoaderResolver} only.
     */
    ClassLoadContext (final Class caller)
    {
        m_caller = caller;
    }
    
    // private: ...............................................................
    

    private final Class m_caller;

} // end of class
// ----------------------------------------------------------------------------