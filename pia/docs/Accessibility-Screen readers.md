# Screen readers

The client has to be fully functional with screen readers.  If you have never used a screen reader before, I recommend starting with VoiceOver on Mac OS X, which is a very good screen reader and has a good introductory tutorial.

VoiceOver has a very rich set of interactions to interact with applications.  It relies on having good annotations from the app to implement these.  It's not sufficient just to put labels and "press" actions on controls, the details like label vs. value, control type, action list & preference order, really make a difference between "barely usable" and "fully functional".

## Crash courses for screen readers

### VoiceOver (Mac)

I recommend starting with VoiceOver on Mac if possible.  It's by far the best screen reader.

<details>
<summary>An _extremely_ short crash course for VoiceOver:</summary>

1. Press Cmd+F5 to enable or disable VoiceOver (it'll give you a chance to do the tutorial, which I recommend you do :grin:)
2. CapsLock+arrows - navigate the controls in a window
   - Left and right will move left/right and wrap around to prior/next lines - these are your go-to keys and you should be able to fully navigate with just these
   - Up and down actually move up and down, but this isn't possible in all contexts.  This should work sensibly, but sometimes you may have to use left/right instead
3. CapsLock+Space - take the default action for a control
   - CapsLock+Shift+Space - list all actions for a control
4. CapsLock+Shift+Down / CapsLock+Shift+Up - enter or leave a group (or table, etc.)
5. CapsLock+I - search for controls
6. CapsLock+M,M - go to the notification area

Full command chart: https://help.apple.com/voiceover/command-charts/#1st-level-commands

</details>

### MS Narrator (Windows)

MS Narrator is a usable (but not great) screen reader on Windows.

<details>
<summary>Crash course for MS Narrator</summary>

This entire section applies to Narrator versions older than the 2018/10 update to Windows 10 ("Creator's Update").  This update supposedly significantly overhauls Narrator, I don't have this update yet so I haven't tried it yet.

1. The default "Narrator key" is Caps Lock.  This may not forward properly through some VM clients, either change the key or forward a USB keyboard directly into the VM.
2. Press Ctrl+Win+Enter to enable Narrator.
3. Tab/Shift-Tab: Cycle through tabstop controls (might be used by low-vision users?)
4. CapsLock+Left/Right: Cycle through all UI elements
    - By default, this enters groups automatically.  "Advanced" navigation mode navigates over groups like VoiceOver.
    - CapsLock+Up/Down does NOT navigate up and down!  It changes the navigation mode, which can leave you stuck if you change it accidentally.
5. CapsLock+Enter: Take the default action for a control.
    - For some controls you might have to let go of CapsLock and press Enter/Space normally to use normal keyboard nave.  It should work in PIA but other apps are very spotty.
    - CapsLock+Space does NOT activate the control!  It toggles "scan mode", keep that turned off.
6. CapsLock+/: Read the current context (control, location, and details)
7. Navigate tables:
    - CapsLock+F3: Right (next in row) / CapsLock+Shift+F3: Left (prev. in row)
    - CapsLock+F4: Down (next in col) / CapsLock+Shift+F4: Up (prev. in col)
    - CapsLock+F7: Read col
    - CapsLock+F8: Read row
8. Navigate tray: Win+B (normal Windows feature, not a Narrator feature)
    - This is pretty buggy with Narrator.  Both Left/Right (normal nav) and CapsLock+Left/Right (Narrator nav) should work, but Narrator frequently loses sync with the normal OS nav, and the OS nav frequently gets stuck in the wrong place.
    - Enter/Space (NOT CapsLock+Space): Pick an icon
    - "Context menu key": Show context menu (the key normally between right Win and right Ctrl, could be anywhere on compact/laptop keyboards)
9. Show item actions: CapsLock+F2
    - Has problems with PIA, steals the focus and causes the dash to hide.

For all commands, check the command list in Narrator's settings.

Narrator moves the insertion point in text controls by default as it reads them, which makes it really clunky to use.  There's an option for this, but it tends to just cause Narrator navigation to break entirely.

Narrator sometimes just stops detecting focus change events.  The accessibility event spy shows they're still being sent, Narrator just isn't processing them.  If this happens, try restarting Narrator.
</details>

### NVDA (Windows)

NVDA is a FOSS screen reader for Windows, basically it's a free clone of JAWS.

<details>
<summary>Crash course for NVDA</summary>

This section applies to the default "Desktop" layout, which uses the numpad extensively, but with **Num Lock off**.  (So "KP 8", etc. below are really "KP up arrow", etc.).

NVDA uses both "tabstop navigation" (tab/shift+tab) and "object navigation" (Insert+KP arrows).  You usually have to use both of these to navigate effectively, because tabstop navigation can only reach focusable controls, but object navigation often gets stuck in nontrivial object heirarchies.

The best strategy is usually to tabstop navigate to a nearby tabstop, then just use object navigation to reach nearby non-interactive controls.

NVDA does not display its cursor at all, so you'll just have to keep track mentally.

1. The default "NVDA key" is Insert.
2. Tab/Shift-Tab: Cycle through tabstop controls.
3. Insert+KP 4/KP 6: Cycle left-right through objects in a group.
4. Insert+KP 2/KP 8: Go down into a group or up out of a group. (https://www.nvaccess.org/files/nvda/documentation/userGuide.html?#ObjectNavigation)
5. Insert+KP Enter: Activate object
6. Insert+KP -: Focus object

</details>

### JAWS (Windows)

JAWS is a (highly) non-free screen reader for Windows, though it's pretty established in the market.

A single-user perpetual license is $900, or annual licenses are $90/year.  The free download gives you a 40-minute trial, after which point you have to reboot to use JAWS again.  This is barely enough time to figure out its clunky interface, let alone test anything.

IMO, JAWS is not worth much dedicated testing effort.  NVDA is a free alternative that has basically the same functionality.  All Windows screen readers use the same API to read applications, so they're all likely to behave in basically the same way.

### Orca (Linux)

Orca is the only screen reader on Linux.

<details>
<summary>Crash course for Orca</summary>

- In KDE, you have to manually install the 'orca' package (for Kubuntu anyway), but then you can enable Orca in System Settings > Accessibility > Screen Reader.  You'll need to log out / in to activate accessibility hints in most applications.
- In GNOME, `Super+Alt+S` should start it, though I haven't tested this (https://help.gnome.org/users/orca/stable/introduction.html.en)
- In any distro, you should be able to install 'orca' and run `orca` manually to start it.
  - Insert+Space opens the Orca preferences if you can't get to it otherwise (this includes a keybinding list)

Like Narrator and NVDA, Orca uses both tabstop and "flat" navigation.  Orca's "flat" navigation is pretty rough, keys variously move between "items" / "lines" / "words" based on whatever Orca thinks constitutes and "item" or "sentence", etc. in that context.  You may have to use a combination of both modes to navigate some things (like the Settings modal dialogs).

Also like NVDA, Orca uses the keypad with **Num Lock off**, meaning "KP 4" should really be "KP Left", etc.  ("KP 5" is listed in Orca's keybindings as "KP Begin", that's what it is when Num Lock is off.)

1. The default "Orca key" is Insert, though many shortcuts actually do not involve the "Orca key".
2. Insert+S: Toggle speech on/off (it's on by default, useful to silence the irritating voice between tests)
3. Tab/Shift+Tab: Cycle through tab stop controls
4. KP Enter: "where am I" - say current focus item
4. KP 4/6, KP 5: Navigate prior/next _word_; read current _word_
   - This depends on what Orca decides a "word" is.  Most of the time, it's a word within a control's text.  Occasionally, it's a whole control (combo boxes).  Other things like "selected"/"not selected" count as words too (checkboxes).
5. KP 7/9, KP 8: Navigate prior/next _item_; read current _item_
   - This depends on what Orca decides an "item" is.  Most of the time, it's a single object.  Sometimes, it's a sentence.  Sometimes, it's a line of grouped objects.
6. KP `/`/`*`: Left/right click current nav item (the item from keypad flat nav, not the focused item)
7. Insert+KP 5: Speak the current flat review "object".
   - Oddly there is no prior/next flat review "object" though.
8. Table navigation:
   - Orca doesn't have any real table navigation.
   - Use regular keyboard nav (arrows + spacebar) to navigate the table.  Orca should read the cells as you navigate to them.
   - Use KP 8 to read the current row, which includes the latency (which can't be read otherwise).

</details>

# General patterns

Generally, annotate the UI like a sighted person would see it.  Make static text elements accessible, don't just put a label on the thing that they label.  Provide labels for images (most of the time).  Keep in mind:
- Blind users have to communicate with support - it's important that the screen reader and visual interfaces are sufficiently similar for them to communicate.
- Screen readers are used by non-blind users with low vision - if they can see an element, the screen reader must be able to read it to them.

Model controls as stock controls if they function similarly - model a toggle button as a check box, model a grid as a table, etc.  Avoid inventing new models with lots of custom actions, these are hard to express and hard for users to learn.

Include most (if not all) information you get from seeing a control.  For example, the Connect button indicates connection states with color and animation; its label reflects this.  Checkboxes and toggle buttons express their "checked" state.  Disabled controls read as "dimmed", as long as you properly set `enabled=false` this is automatic.  (If you can't set `enabled=false` for some reason, use the `disabled` NativeAcc property to indicate that it's disabled.)

"Value indicator" texts must have labels.  Otherwise, they're not searchable (you'd have to search for the value, which makes no sense).  These don't really have a great parallel in other native apps, usually read only text fields are used for this (which is how value indicators are annotated).

Grouping must be effective and sensible.  Grouping is important to navigate large UIs quickly and efficiently.

Virtually everything should be annotated - keep in mind low vision users as above.  Occasional exceptions:
- Strictly background images - like the header bar background.  Though this changes with state, its state is expressed by the header title.
- Individual components of a "control" - like a "button" made of a text and an image.  The whole control should be annotated, usually the individual text/image don't need to be annotated since they're described by the control.
- Elements strictly for hover effects - the information must be available some other way.  Info Tips' popups aren't annotated (the Info Tip itself contains that text); the Performance module's pointing-overlay text isn't annotated (the bars' values are that text instead).
- Table cell decorations - the region flags are treated as part of the "regions" column, these carry no additional information beyond the region name.  No-PF arrows are also treated as part of the "regions" column, primarily because they do not visually form a column.

# Control labels

A "control label" is a static text element that labels an adjacent control; where the control has its name annotation set to the same text as the label.

Labels should be created with `LabelText` (which is annotated as a `NativeAcc.Label`).  These annotations are important for Windows/Linux, but they're suppressed on Mac.

Labels are hidden on Mac because:
- they're particularly cumbersome in the Connections tab in Settings (due to VO not reading the two-column layout in a column-major order)
- VO reliably and consistently reads control titles as they're navigated

They're less obtrusive on Windows/Linux, because those screen readers favor Tab key navigation, which skips labels.  They're also more important on those platforms because screen readers aren't as consistent about reading control titles.

Skipping them is imperfect on Mac OS because it prevents a low-vision user from pointing to the title and having VO read it (there's an option for VO to follow the mouse cursor).  However, with the control immediately adjacent, this should be OK.  The perfect solution might be for the control's bounds to include the label as well, but that requires a lot of layout changes throughout the app and would be hard to maintain for relatively little benefit.

# Making UI accessible

Many of the tips for [keyboard nav](New ui: keyboard nav) apply for screen readers too.
- Use pre-built controls (`ButtonArea`, `StaticText`, `ValueText`, `StaticImage`, etc.) instead of raw elements like `MouseArea` and `Text` (whenever possible).
- Set `name`/`label` properties on those controls where applicable (mainly `ButtonArea`, `ValueText`, and `StaticImage`).  Names are always translated.  Grab a label from a `StaticText` when appropriate.  Make sure the label is translated with `uiTr()`, and if it's a screen-reader-specific string, include an appropriate translator comment (it obviously won't have a screenshot).
- Make sure hidden controls actually have `visible=false`, not just `opacity=0`.  (This can be inherited from a parent element.)

# Annotating groups

To make an item an accessibility group, just add `NativeAcc.Group.name: <...>` to it.  (And `import PIA.NativeAcc 1.0 as NativeAcc` to your imports if it's not already there.)

An accessibility element with an empty name is ignored.  If you conditionally need an accessibility group, set its name to `''` when it's not needed.  (This works for any NativeAcc annotation.)

# Annotating custom UI

If there isn't a stock type for your control, you'll need to annotate it manually.  This is usually the case if you do use raw `Text` or `MouseArea`.

To do this, choose one of the `NativeAcc` annotation types, which are listed in `NativeAcc::init()` (nativeacc.cpp).  Annotate a control by setting the `NativeAcc.<type>.*` attached properties (for some controls, `name` is the only property).

The exact `Item` you choose to annotate is important - usually it should be the Item that gets the keyboard focus.  The annotated Item determines the annotation's screen bounds as well as its enabled, focusable action, focused state, etc.  See `AccessibleItem` for the details on this.

When possible, you should test custom UIs with multiple screen readers on multiple platforms.  QAccessible ignores various details on various platforms, and different screen readers ignore more details, so it's important to fully validate custom UI.

# New annotation types

If there isn't a `NativeAcc` model that fits your control, you may need to add a new one.  (Note that there can be more than one model for a given accessibility role, which simplifies QML when the different models fit different UI patterns closely.)

This gets pretty advanced pretty quickly.  You _must_ test this with multiple screen readers - in particular, QAccessible's Mac backend is very poor and requires a lot of polyfilling to get decent functionality (see `mac_accessibility.mm` and `mac_accessibility_decorator.mm`).

- If you just need a new role, create a new attached type with that role.
  - For example, if you need a new Button role that is otherwise the same, create a new type derived from `SingleActionItem` in buttons.h/buttons.cpp with the new role, and specify what its "press" action is.
  - Keep in mind that Qt maps many roles to the same thing on Mac (even though it too has lots of different roles), you may need to polyfill this to get the right role on Mac.
- Simple properties, such as extra state flags, can be added as a regular attached property that uses `AccessibleItem::setState()`, like `CheckableActionItem`'s `checked` property.
  - However, most state fields are ignored on Mac, you'll need to polyfill those.

You _must_ test all these things with multiple screen readers.  For new roles, you are likely to run into problems on Mac.  VoiceOver may expect certain attributes that Qt does not provide, and it will assume defaults if they're not there.  (For example, in a stock Qt application, all scroll bars say they are "horizontal", because Qt does not provide the orientation property.)

# Tables

Tables are a powerful interface and are virtually required to navigate large grids effectively.  Annotating them from QML is relatively involved - you have to define the rows, columns, and all cells with appropriate accessibility roles.

`TableAttached` and the cell types (table.h) has details on this.  Some of this is simplified to the model used by the regions list, since it is currently our only table (it can only select rows, has no headings, etc.)
- The table indicates its columns with an array of `TableColumn` definitions.  These can change dynamically but usually are relatively static.
  - The columns do define an `Item` that specifies the column's screen bounds, but it has no known effect on any platform right now, so we just use the list itself as a placeholder.
- The table lists the rows, and each row lists its individual cells (using property names defined by each column).
  - For `RegionListView`, the individual `RegionRowBase` objects define `TableRow` and `TableCell` objects, and Table assembles those into the rows array.  This simplifies the model because the `RegionRowBase` objects have the logic necessary to provide the cell data/actions already.
- Each table cell can have a different role (or theoretically could be a group of items, though there's no cell type for this currently).  Cell types are defined in `tablecells.h` - at a high level these are similar to the normal `NativeAcc` annotations, but the implementation is different.
  - The regions list uses a button cell for the region, a static text cell for the latency, and a checkbox cell for the favorite button.

# In-window overlays

There are several UI elements that fit into the category of "in-window overlays":
 - Popup menus (header menu, text field context menus)
 - Drop-down lists
 - Overlay dialogs (in the settings window, for DNS and TAP adapter maintenance)

From an annotation standpoint, these should "just work" when annotated normally, `WindowAccImpl` handles this case.  It's important that the elements are properly hidden or destroyed when they're not visible.

These elements are modal in their respective windows - the user cannot interact with the normal controls until the overlay is dismissed.  `WindowAccImpl` handles this by swapping out the entire window content when any modal overlay becomes visible, then swapping back when the overlay is closed.  This isn't quite as good UX as a legitimate popup, but we're limited by the fact that these are in-window, screen readers (that I tested anyway) simply are not designed for this.

A "modal overlay" is detected by `WindowAccImpl` as "any Item in the overlay layer with an active NativeAcc annotation".  Modeless and interactive overlays are not supported, these would be treated as modal.  (Please don't do that - the detection is straightforward, but it'd be very hard to sensibly express to a screen reader.)

Overlay components with no annotations have no effect, such as Info Tip's popups.  Note that these need to be expressed to the screen reader some other way (Info Tip's in-window element is labelled with the popup text).

# The QML Accessible type

The QML Accessible type is unusable.  A full explanation of this (and many of its limitations) are in nativeacc.h, but the final nails in the coffin are:
- It has absolutely no support for many critical features: disabled controls, the "link" type, tables, modal overlays, etc. - these have to be implemented manually on QAccessible.
- QML Accessible and raw QAccessible annotations can't be mixed.  QML Accessible objects only report other QML Accessible objects as their own children, so they prevent us from adding custom annotations.

The stock annotations provided by Qt Quick controls are pretty terrible anyway (menus and drop downs in particular are really broken).

We can't fully remove the QML Accessible interface factories, but as long as NativeAcc annotations are defined declaratively (avoid setting them in Component.onCompleted, etc.), they can override QML Accessible annotations.  The stock controls have been re-annotated with NativeAcc where they are used.

# Mac polyfills

A lot of functionality had to be filled in on Mac to get VoiceOver to work well - the QAccessible Mac backend is terrible.  This is done in `mac_accessibility_decorator.mm` by subclassing the Mac accessibility elements at runtime to override some functionality.

Qt does not emit create/destroy events at all on Mac.  This had to be filled in for VoiceOver to work with modal overlays.  Otherwise, (for example) when the DNS popups were displayed and then destroyed, VoiceOver would remain stuck in the hidden DNS popup controls.  (It correctly handles the currently-highlighted control disappearing from its parents' children, but in this case a huge part of the accessibility tree was "severed from" the window's full tree.  Then it can't find its way back out to the window and does not realize the controls are no longer in the main tree.  Destroy events tell it that the highlighted control is destroyed, and it will move back up to the enclosing control.)

There are a bunch of other things that had to be filled in or fixed too:
- Tables aren't supported at all.  (Qt doesn't implement the row or column attributes.)
- The regions list table is actually an outline (it has collapsible groups and levels), Qt maps the table type to the Table role though.
- Custom actions aren't supported at all (use sparingly, but important in a few specific cases).
- Scroll bar orientations aren't supported.  (They all say "horizontal".)

There are other limitations too, but some of these were worked around with careful QAccessible use, and some very subtle ones are just not handled right now (due to very low payback per time invested :cry:).

Note that Qt uses the "legacy" `NSAccessibility` "informal protocol", not the new `NSAccessibility` proper protocol (which have the same name, don't get confused).

- This is the legacy `NSAccessibility` protocol: https://developer.apple.com/documentation/appkit/accessibility/nsaccessibility?language=objc
  - Realistically, you'll have to look here for any actual information: `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/AppKit.framework/Headers/NSAccessibilityConstants.h` - comments describe the accessibility attributes and what their parameters/values are
- This is the NEW `NSAccessibility` protocol, this is the WRONG DOCUMENT for working with Qt: https://developer.apple.com/documentation/appkit/nsaccessibility?language=objc

To make this _even more complicated_, the Mac tray accessibility uses the _new_ protocol, because it is implemented with an `NSStatusBarButton` (eventually an `NSButton` -> `NSControl` -> `NSView`).  (It's fortunate that we have a native implementation for this; the `QSystemTrayIcon` accessibility is worse than `QAccessible` on Mac, you can't press the button at all.)
