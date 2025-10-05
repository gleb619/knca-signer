package knca.signer.kalkan;


import lombok.extern.slf4j.Slf4j;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility class to handle reflection operations for Kalkan classes using Java 21 reflection API
 * Provides caching for performance and centralized error handling
 * Includes enhanced diagnostic logging for reflection failures
 */
@Slf4j
public class ReflectionHelper {

    private static final ConcurrentHashMap<String, Class<?>> classCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, MethodHandle> methodCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, MethodHandle> constructorCache = new ConcurrentHashMap<>();
    private static final MethodHandles.Lookup lookup = MethodHandles.lookup();

    /**
     * Load a Kalkan class using reflection
     */
    public static Class<?> loadKalkanClass(String className) throws ClassNotFoundException {
        return classCache.computeIfAbsent(className, name -> {
            try {
                return Class.forName(name);
            } catch (ClassNotFoundException e) {
                log.error("ERROR: Kalkan class not found: {}, Available classpath: {}", name, System.getProperty("java.class.path"));
                throw new KalkanException("Kalkan class not found: " + name, e);
            }
        });
    }

    /**
     * Instantiate a class reflectively with no arguments
     */
    public static Object newInstance(Class<?> clazz) {
        try {
            return clazz.getDeclaredConstructor().newInstance();
        } catch (NoSuchMethodException e) {
            log.error("ERROR: No no-arg constructor found for {}", clazz.getName());
            throw new KalkanException("Failed to instantiate %s - no default constructor".formatted(clazz.getName()),
                    e, getAvailableConstructors(clazz), null);
        } catch (Exception e) {
            log.error("ERROR: Failed to instantiate {} due to: {}", clazz.getName(), e.getMessage());
            throw new KalkanException("Failed to instantiate %s".formatted(clazz.getName()), e);
        }
    }

    /**
     * Instantiate a class reflectively with arguments using MethodHandles
     */
    public static Object newInstance(Class<?> clazz, Class<?>[] paramTypes, Object[] args) {
        try {
            if (paramTypes == null || args == null) return newInstance(clazz);

            String key = clazz.getName() + Arrays.toString(paramTypes);
            MethodHandle constructorHandle = constructorCache.computeIfAbsent(key, k -> {
                try {
                    return lookup.findConstructor(clazz, MethodType.methodType(void.class, paramTypes));
                } catch (NoSuchMethodException | IllegalAccessException e) {
                    log.error("ERROR: Constructor with parameters {} not found for {}", Arrays.toString(paramTypes), clazz.getName());
                    throw new KalkanException("Failed to find constructor handle for " + clazz.getName(),
                            e, getAvailableConstructors(clazz), null);
                }
            });
            return constructorHandle.invokeWithArguments(args);
        } catch (Throwable e) {
            log.error("ERROR: Failed to instantiate {} with provided args due to: {}", clazz.getName(), e.getMessage());
            throw new KalkanException("Failed to instantiate %s with args".formatted(clazz.getName()), e);
        }
    }

    /**
     * Invoke a method reflectively using MethodHandles
     */
    public static Object invokeMethod(Object instance, String methodName, Class<?>[] paramTypes, Object[] args) {
        try {
            Object[] fArgs = args == null ? new Object[0] : args;
            Class<?>[] fTypes = paramTypes == null ? inferParamTypes(fArgs) : paramTypes;
            Class<?> instanceClass = instance.getClass();
            String key = instanceClass.getName() + "#" + methodName + Arrays.toString(fTypes);

            MethodHandle handle = methodCache.computeIfAbsent(key, k -> {
                try {
                    Method method = findMethod(instanceClass, methodName, fTypes);
                    return lookup.findVirtual(instanceClass, methodName, MethodType.methodType(method.getReturnType(), method.getParameterTypes()));
                } catch (NoSuchMethodException | IllegalAccessException | SecurityException e) {
                    log.error("ERROR: Method '{}' with parameters {} not found on {}", methodName, Arrays.toString(fTypes), instanceClass.getName());
                    throw new KalkanException("Failed to find method handle for " + methodName + " on " + instanceClass.getName(),
                            e, null, getAvailableMethods(instanceClass, methodName));
                }
            });

            Object[] unwrapped = new Object[fArgs.length + 1];
            unwrapped[0] = instance;
            for (int i = 0; i < fArgs.length; i++) unwrapped[i + 1] = unwrapValue(fArgs[i]);
            return handle.invokeWithArguments(unwrapped);
        } catch (Throwable e) {
            log.error("ERROR: Failed to invoke `{}` on `{}` due to: `{}`", methodName, instance.getClass().getName(), e.getMessage());
            throw new KalkanException("Failed to invoke %s on %s".formatted(methodName, instance.getClass().getName()), e);
        }
    }

    /**
     * Invoke static method reflectively using MethodHandles
     */
    public static Object invokeStaticMethod(Class<?> clazz, String methodName, Class<?> returnType, Class<?>[] paramTypes, Object[] args) {
        try {
            Class<?>[] fTypes = paramTypes == null ? new Class<?>[0] : paramTypes;
            Object[] fArgs = args == null ? new Object[0] : args;
            String key = clazz.getName() + "#" + methodName + Arrays.toString(fTypes);

            MethodHandle handle = methodCache.computeIfAbsent(key, k -> {
                try {
                    return lookup.findStatic(clazz, methodName, MethodType.methodType(returnType, fTypes));
                } catch (NoSuchMethodException | IllegalAccessException e) {
                    log.debug("ERROR: Static method '{}' with parameters {} not found on {}", methodName, Arrays.toString(fTypes), clazz.getName());
                    throw new KalkanException("Failed to find static method handle for " + methodName + " on " + clazz.getName(),
                            e, null, getAvailableMethods(clazz, methodName));
                }
            });
            return handle.invokeWithArguments(fArgs);
        } catch (Throwable e) {
            log.error("ERROR: Failed to invoke static {} on {} due to: {}", methodName, clazz.getName(), e.getMessage());
            throw new KalkanException("Failed to invoke static %s on %s".formatted(methodName, clazz.getName()), e);
        }
    }

    private static Class<?>[] inferParamTypes(Object[] args) {
        Class<?>[] types = new Class<?>[args.length];
        for (int i = 0; i < args.length; i++) {
            Object u = unwrapValue(args[i]);
            types[i] = getPrimitiveClassIfWrapper(u.getClass());
        }
        return types;
    }

    private static Method findMethod(Class<?> clazz, String methodName, Class<?>[] paramTypes) throws NoSuchMethodException {
        try {
            return clazz.getMethod(methodName, paramTypes);
        } catch (NoSuchMethodException e) {
            for (Method method : clazz.getMethods()) {
                if (method.getName().equals(methodName)) {
                    Class<?>[] mParamTypes = method.getParameterTypes();
                    if (mParamTypes.length == paramTypes.length) {
                        boolean match = true;
                        for (int i = 0; i < mParamTypes.length; i++) {
                            if (!mParamTypes[i].isAssignableFrom(paramTypes[i])) {
                                match = false;
                                break;
                            }
                        }
                        if (match) return method;
                    }
                }
            }
            throw new NoSuchMethodException("No method found: %s with assignable parameter types %s".formatted(methodName, Arrays.toString(paramTypes)));
        }
    }

    private static Class<?> getPrimitiveClassIfWrapper(Class<?> clazz) {
        if (clazz == Boolean.class) return boolean.class;
        if (clazz == Byte.class) return byte.class;
        if (clazz == Character.class) return char.class;
        if (clazz == Short.class) return short.class;
        if (clazz == Integer.class) return int.class;
        if (clazz == Long.class) return long.class;
        if (clazz == Float.class) return float.class;
        if (clazz == Double.class) return double.class;
        return clazz;
    }

    public static boolean is(Class<?> clazz, Object object) {
        return clazz.isAssignableFrom(object.getClass());
    }

    public static Object unwrapValue(Object object) {
        return object instanceof KalkanProxy p ? p.getRealObject() : object;
    }

    private static List<String> getAvailableConstructors(Class<?> clazz) {
        List<String> list = new ArrayList<>();
        for (Constructor<?> c : clazz.getConstructors()) list.add(c.toString());
        return list;
    }

    private static List<String> getAvailableMethods(Class<?> clazz, String methodName) {
        List<String> list = new ArrayList<>();
        for (Method m : clazz.getMethods()) {
            if (m.getName().equals(methodName) || methodName == null) list.add(m.toString());
        }
        return list;
    }
}
