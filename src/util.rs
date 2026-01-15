/// Applies a configuration attribute to all items within the block.
///
/// This macro allows you to conditionally compile a group of items
/// without nesting them in a module.
///
/// # Example
///
/// ```
/// use libvoid::cfg_block;
///
/// cfg_block! {
///     #[cfg(target_os = "linux")]
///     {
///         fn linux_helper() -> u32 { 42 }
///
///         struct LinuxData {
///             value: i32,
///         }
///     }
/// }
///
/// // On Linux, these items are available:
/// #[cfg(target_os = "linux")]
/// {
///     assert_eq!(linux_helper(), 42);
///     let _data = LinuxData { value: 10 };
/// }
/// ```
///
/// This expands to:
///
/// ```
/// #[cfg(target_os = "linux")]
/// fn linux_helper() -> u32 { 42 }
///
/// #[cfg(target_os = "linux")]
/// struct LinuxData { value: i32 }
/// # #[cfg(target_os = "linux")]
/// # { assert_eq!(linux_helper(), 42); }
/// ```
#[macro_export]
macro_rules! cfg_block {
    (#[$meta:meta] { $($item:item)* }) => {
        $(
            #[$meta]
            $item
        )*
    };
}
